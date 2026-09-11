package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

type Kind string

const (
	KindEvent     Kind = "event"
	KindBehaviour Kind = "behaviour_window"
	KindSequence  Kind = "frame_sequence"
	KindDevice    Kind = "device"
)

type Client interface {
	Embed(ctx context.Context, texts []string, kind Kind) ([][]float32, error)
	Health(ctx context.Context) error
}

type NoopClient struct {
	Dimensions int
}

func (c NoopClient) Embed(_ context.Context, texts []string, _ Kind) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i := range texts {
		out[i] = make([]float32, c.Dimensions)
	}
	return out, nil
}

func (c NoopClient) Health(context.Context) error { return nil }

type HTTPClient struct {
	BaseURL    string
	Model      string
	Dimensions int
	// MaxTokens is the per-input token budget. Inputs whose estimated
	// token count exceeds the budget are split into chunks, and the chunk
	// embeddings are mean-pooled so each input still yields a single
	// vector. Zero selects DefaultMaxTokens (512, the nomic-embed
	// llama.cpp context size).
	MaxTokens int
	Client    *http.Client
}

type embeddingsRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embeddingsResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Embeddings [][]float32 `json:"embeddings"`
	Error      any         `json:"error"`
}

func NewHTTPClient(baseURL, model string, dimensions, maxTokens int) *HTTPClient {
	return &HTTPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Model:      model,
		Dimensions: dimensions,
		MaxTokens:  maxTokens,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// embedRequestBatch bounds how many chunk inputs are posted per HTTP request.
const embedRequestBatch = 32

func (c *HTTPClient) Embed(ctx context.Context, texts []string, _ Kind) ([][]float32, error) {
	if c.BaseURL == "" {
		return nil, errors.New("embedding backend URL is empty")
	}
	// Split every text into chunks that respect the model token budget,
	// remember which chunk range belongs to which input, embed the chunks,
	// then pool each range back into a single vector.
	offsets := make([]int, len(texts)+1)
	inputs := make([]string, 0, len(texts))
	for i, text := range texts {
		chunks := ChunkText(text, c.MaxTokens)
		offsets[i+1] = offsets[i] + len(chunks)
		inputs = append(inputs, chunks...)
	}
	vectors, err := c.embedInputs(ctx, inputs)
	if err != nil {
		return nil, err
	}
	pooled := make([][]float32, len(texts))
	for i := range texts {
		pooled[i] = meanVectors(vectors[offsets[i]:offsets[i+1]], c.Dimensions)
	}
	return pooled, nil
}

// embedInputs posts inputs in bounded sub-batches. Every input is a single
// chunk that already respects the model token budget, so the backend never
// receives an input larger than its context.
func (c *HTTPClient) embedInputs(ctx context.Context, inputs []string) ([][]float32, error) {
	vectors := make([][]float32, 0, len(inputs))
	for start := 0; start < len(inputs); start += embedRequestBatch {
		end := start + embedRequestBatch
		if end > len(inputs) {
			end = len(inputs)
		}
		part, err := c.embedOnce(ctx, inputs[start:end])
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, part...)
	}
	return vectors, nil
}

func (c *HTTPClient) embedOnce(ctx context.Context, inputs []string) ([][]float32, error) {
	body, err := json.Marshal(embeddingsRequest{Model: c.Model, Input: inputs})
	if err != nil {
		return nil, err
	}
	endpoint := c.BaseURL
	if !strings.HasSuffix(endpoint, "/v1/embeddings") && !strings.HasSuffix(endpoint, "/api/embed") {
		endpoint += "/v1/embeddings"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("embedding backend returned %s; read response body: %w", resp.Status, readErr)
		}
		if message := responseErrorText(body); message != "" {
			return nil, fmt.Errorf("embedding backend returned %s: %s", resp.Status, message)
		}
		return nil, fmt.Errorf("embedding backend returned %s", resp.Status)
	}
	var parsed embeddingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	vectors := parsed.Embeddings
	if len(vectors) == 0 && len(parsed.Data) > 0 {
		vectors = make([][]float32, len(parsed.Data))
		for i, item := range parsed.Data {
			vectors[i] = item.Embedding
		}
	}
	if len(vectors) != len(inputs) {
		return nil, fmt.Errorf("embedding backend returned %d vectors for %d inputs", len(vectors), len(inputs))
	}
	for i, vec := range vectors {
		if len(vec) != c.Dimensions {
			return nil, fmt.Errorf("embedding %d has %d dimensions, expected %d", i, len(vec), c.Dimensions)
		}
	}
	return vectors, nil
}

// meanVectors averages chunk embeddings into a single vector. A single chunk
// is copied through unchanged, so short inputs behave exactly as before.
func meanVectors(chunkVectors [][]float32, dimensions int) []float32 {
	if len(chunkVectors) == 1 {
		return append([]float32(nil), chunkVectors[0]...)
	}
	mean := make([]float32, dimensions)
	for _, vec := range chunkVectors {
		for i := range mean {
			if i < len(vec) {
				mean[i] += vec[i]
			}
		}
	}
	count := float32(len(chunkVectors))
	for i := range mean {
		mean[i] /= count
	}
	return mean
}

func responseErrorText(body []byte) string {
	message := strings.TrimSpace(string(body))
	var parsed embeddingsResponse
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error != nil {
		switch value := parsed.Error.(type) {
		case string:
			message = value
		default:
			encoded, err := json.Marshal(value)
			if err == nil {
				message = string(encoded)
			} else {
				message = fmt.Sprint(value)
			}
		}
	}
	if len(message) > 2048 {
		i := 2048
		for i > 0 && !utf8.RuneStart(message[i]) {
			i--
		}
		return message[:i]
	}
	return message
}

func (c *HTTPClient) Health(ctx context.Context) error {
	if c.BaseURL == "" {
		return errors.New("embedding backend URL is empty")
	}
	_, err := c.Embed(ctx, []string{"kind: event\nquery: healthcheck"}, KindEvent)
	return err
}
