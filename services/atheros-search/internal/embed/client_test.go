package embed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recordedEmbeddingsRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

// newRecordingBackend returns a fake OpenAI-compatible embeddings backend
// that echoes a vector of [n, n] for the n-th input of each request.
func newRecordingBackend(t *testing.T, requests *[]recordedEmbeddingsRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req recordedEmbeddingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		*requests = append(*requests, req)
		resp := struct {
			Data []struct {
				Embedding []float32 `json:"embedding"`
				Index     int       `json:"index"`
			} `json:"data"`
		}{}
		for i := range req.Input {
			value := float32(i + 1)
			resp.Data = append(resp.Data, struct {
				Embedding []float32 `json:"embedding"`
				Index     int       `json:"index"`
			}{Embedding: []float32{value, value}, Index: i})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func longEventText(lines int) string {
	var parts []string
	for i := 0; i < lines; i++ {
		parts = append(parts, fmt.Sprintf("detail_%02d: sensor-1 aa:bb:cc:dd:ee:%02x packet digest entry", i, i))
	}
	return strings.Join(parts, "\n")
}

func TestEmbedChunksLongTextsAndPoolsVectors(t *testing.T) {
	var requests []recordedEmbeddingsRequest
	server := newRecordingBackend(t, &requests)
	defer server.Close()

	client := NewHTTPClient(server.URL, "nomic-embed-text-v2-moe", 2, 64)
	short := "kind: event\nquery: healthcheck"
	long := longEventText(60)
	vectors, err := client.Embed(context.Background(), []string{short, long}, KindEvent)
	if err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("expected one vector per input text, got %d", len(vectors))
	}

	budget := chunkBudget(64)
	totalInputs := 0
	for _, req := range requests {
		for _, input := range req.Input {
			if got := EstimateTokens(input); got > budget {
				t.Fatalf("backend received input of %d tokens, budget %d: %q", got, budget, input)
			}
			totalInputs++
		}
	}
	if totalInputs < 2 {
		t.Fatalf("expected the long text to be chunked, got %d total inputs", totalInputs)
	}

	// Short text: single chunk with echo value [1, 1].
	if vectors[0][0] != 1 || vectors[0][1] != 1 {
		t.Fatalf("short text vector = %v, want [1 1]", vectors[0])
	}

	// Long text: mean over its chunks. Chunk j of the long text echoes
	// [j+2, j+2] (the first input belonged to the short text).
	chunks := ChunkText(long, 64)
	if len(chunks) < 2 {
		t.Fatalf("expected long text to produce multiple chunks, got %d", len(chunks))
	}
	expected := (2 + float32(len(chunks)+1)) / 2
	if vectors[1][0] != expected || vectors[1][1] != expected {
		t.Fatalf("pooled vector = %v, want [%v %v]", vectors[1], expected, expected)
	}
}

func TestEmbedChunksWithinSingleRequestBatch(t *testing.T) {
	var requests []recordedEmbeddingsRequest
	server := newRecordingBackend(t, &requests)
	defer server.Close()

	client := NewHTTPClient(server.URL, "nomic-embed-text-v2-moe", 2, 64)
	texts := make([]string, 8)
	for i := range texts {
		texts[i] = longEventText(40)
	}
	if _, err := client.Embed(context.Background(), texts, KindEvent); err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	for _, req := range requests {
		if len(req.Input) > embedRequestBatch {
			t.Fatalf("request posted %d inputs, bound is %d", len(req.Input), embedRequestBatch)
		}
	}
}

func TestEmbedPropagatesBackendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"input is larger than the max context size"},"n_ctx":512}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL, "nomic-embed-text-v2-moe", 2, 64)
	_, err := client.Embed(context.Background(), []string{"kind: event\nquery: x"}, KindEvent)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if !strings.Contains(err.Error(), "input is larger than the max context size") {
		t.Fatalf("error should surface backend message, got: %v", err)
	}
}
