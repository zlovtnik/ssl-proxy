package embed

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedEmbeddingsRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

// llamaFake implements the verified llama.cpp surface: /tokenize, /detokenize
// and /v1/embeddings, with stable word-to-token ids so the tests can assert
// exact tokenizer-counted budgets.
type llamaFake struct {
	mu         sync.Mutex
	ids        map[string]int
	words      map[int]string
	next       int
	embeddings []recordedEmbeddingsRequest

	failEmbeds      int
	embedDelay      time.Duration
	tokenError      bool
	detokError      bool
	emptyTokenize   bool
	emptyDetokenize bool
}

func (f *llamaFake) tokenize(content string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	tokens := make([]int, 0, 16)
	for _, word := range strings.Fields(content) {
		id, ok := f.ids[word]
		if !ok {
			f.next++
			id = f.next
			f.ids[word] = id
			f.words[id] = word
		}
		tokens = append(tokens, id)
	}
	return tokens
}

func (f *llamaFake) detokenize(tokens []int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	words := make([]string, len(tokens))
	for i, id := range tokens {
		words[i] = f.words[id]
	}
	return strings.Join(words, " ")
}

func (f *llamaFake) server() *httptest.Server {
	f.mu.Lock()
	if f.ids == nil {
		f.ids = make(map[string]int)
	}
	if f.words == nil {
		f.words = make(map[int]string)
	}
	f.mu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/tokenize", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		failed := f.tokenError
		empty := f.emptyTokenize
		f.mu.Unlock()
		if failed {
			http.Error(w, `{"error":"tokenize unavailable"}`, http.StatusInternalServerError)
			return
		}
		tokens := f.tokenize(body.Content)
		if empty {
			tokens = nil
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Tokens []int `json:"tokens"`
		}{Tokens: tokens})
	})
	mux.HandleFunc("/detokenize", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tokens []int `json:"tokens"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		failed := f.detokError
		empty := f.emptyDetokenize
		f.mu.Unlock()
		if failed {
			http.Error(w, `{"error":"detokenize unavailable"}`, http.StatusInternalServerError)
			return
		}
		content := f.detokenize(body.Tokens)
		if empty {
			content = ""
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Content string `json:"content"`
		}{Content: content})
	})
	mux.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		var req recordedEmbeddingsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.embeddings = append(f.embeddings, req)
		delay, failing := f.embedDelay, f.failEmbeds > 0
		if failing {
			f.failEmbeds--
		}
		f.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		if failing {
			http.Error(w, `{"error":"backend overloaded"}`, http.StatusServiceUnavailable)
			return
		}
		type item struct {
			Embedding []float32 `json:"embedding"`
			Index     int       `json:"index"`
		}
		resp := struct {
			Data []item `json:"data"`
		}{}
		for i, input := range req.Input {
			value := float32(len(strings.Fields(input)))
			resp.Data = append(resp.Data, item{Embedding: []float32{value, value}, Index: i})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

func (f *llamaFake) requests() []recordedEmbeddingsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedEmbeddingsRequest(nil), f.embeddings...)
}

func newTestClient(server *httptest.Server) *HTTPClient {
	return NewHTTPClient(server.URL, "nomic-embed-text-v2-moe", 2, 512)
}

func inputTokens(f *llamaFake, input string) int {
	return len(f.tokenize(input))
}

func TestEmbedPoolsChunkVectorsInDeterministicOrder(t *testing.T) {
	fake := &llamaFake{}
	server := fake.server()
	defer server.Close()
	client := newTestClient(server)
	short := "kind: event query"
	medium := syntheticSequenceText(490)
	long := syntheticSequenceText(1000)
	vectors, err := client.Embed(context.Background(), []string{short, medium, long}, KindEvent)
	if err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("expected one pooled vector per input, got %d", len(vectors))
	}
	expected := []float32{
		3,
		(480 + 10) / 2,
		float32(480+480+40) / 3,
	}
	for i, want := range expected {
		diff := vectors[i][0] - want
		if diff < -0.001 || diff > 0.001 {
			t.Fatalf("pooled vector %d = %v, want mean %v", i, vectors[i], want)
		}
	}
}

func TestEmbedRequestPackingStaysWithinTokenBudget(t *testing.T) {
	fake := &llamaFake{}
	server := fake.server()
	defer server.Close()
	client := newTestClient(server)
	texts := make([]string, 12)
	for i := range texts {
		texts[i] = syntheticSequenceText(600)
	}
	if _, err := client.Embed(context.Background(), texts, KindSequence); err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	requests := fake.requests()
	totalChunks := 0
	for _, req := range requests {
		batchTokens := 0
		for _, input := range req.Input {
			tokens := inputTokens(fake, input)
			if tokens > ChunkTokenLimit {
				t.Fatalf("embedding input has %d tokens, chunk limit is %d", tokens, ChunkTokenLimit)
			}
			batchTokens += tokens
			totalChunks++
		}
		if batchTokens > RequestTokenLimit {
			t.Fatalf("request carried %d content tokens, limit is %d", batchTokens, RequestTokenLimit)
		}
	}
	if totalChunks != 24 {
		t.Fatalf("expected 24 chunked inputs, got %d", totalChunks)
	}
	if len(requests) < 2 {
		t.Fatalf("expected packing across requests, got %d", len(requests))
	}
}

func TestEmbedKeepsTwoRequestsInFlight(t *testing.T) {
	fake := &llamaFake{}
	server := fake.server()
	defer server.Close()
	var mu sync.Mutex
	inFlight := 0
	twoInFlight := make(chan struct{})
	var once sync.Once
	inner := server.Config.Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/embeddings" {
			mu.Lock()
			inFlight++
			if inFlight >= 2 {
				once.Do(func() { close(twoInFlight) })
			}
			mu.Unlock()
			select {
			case <-twoInFlight:
			case <-time.After(5 * time.Second):
			}
			mu.Lock()
			inFlight--
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})

	client := newTestClient(server)
	texts := make([]string, 10)
	for i := range texts {
		texts[i] = syntheticSequenceText(1000)
	}
	if _, err := client.Embed(context.Background(), texts, KindSequence); err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	select {
	case <-twoInFlight:
	case <-time.After(time.Second):
		t.Fatal("embedding requests were not executed concurrently")
	}
}

func TestChunkingSynthetic173443TokenSequence(t *testing.T) {
	fake := &llamaFake{}
	server := fake.server()
	defer server.Close()
	client := newTestClient(server)
	text := syntheticSequenceText(173443)
	if _, err := client.Embed(context.Background(), []string{text}, KindSequence); err != nil {
		t.Fatalf("Embed returned error: %v", err)
	}
	requests := fake.requests()
	if len(requests) < 2 {
		t.Fatalf("expected the synthetic sequence to span requests, got %d", len(requests))
	}
	for _, request := range requests {
		total := 0
		for _, input := range request.Input {
			count := inputTokens(fake, input)
			if count > ChunkTokenLimit {
				t.Fatalf("embedding input has %d tokens, limit is %d", count, ChunkTokenLimit)
			}
			total += count
		}
		if total > RequestTokenLimit {
			t.Fatalf("request has %d content tokens, limit is %d", total, RequestTokenLimit)
		}
	}
}

func TestValidateTokenizerRejectsUnavailableEndpoints(t *testing.T) {
	fake := &llamaFake{tokenError: true}
	server := fake.server()
	defer server.Close()
	err := newTestClient(server).ValidateTokenizer(context.Background())
	if err == nil || !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("ValidateTokenizer error = %v, want unavailable error", err)
	}
}
