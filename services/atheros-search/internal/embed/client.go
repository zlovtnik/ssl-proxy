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
	"sync"
	"time"
	"unicode/utf8"
)

type Kind string

const (
	KindEvent     Kind = "event"
	KindBehaviour Kind = "behaviour"
	KindSequence  Kind = "sequence"
	KindDevice    Kind = "device"
)

type Client interface {
	Embed(ctx context.Context, texts []string, kind Kind) ([][]float32, error)
	Health(ctx context.Context) error
}

type NoopClient struct{ Dimensions int }

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
	MaxTokens  int // retained for configuration compatibility; chunks are always 480 content tokens.
	Client     *http.Client
	tokenizer  Tokenizer
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
type tokenizeRequest struct {
	Content string `json:"content"`
}
type tokenizeResponse struct {
	Tokens []int `json:"tokens"`
}
type detokenizeRequest struct {
	Tokens []int `json:"tokens"`
}
type detokenizeResponse struct {
	Content string `json:"content"`
}

func NewHTTPClient(baseURL, model string, dimensions, maxTokens int) *HTTPClient {
	c := &HTTPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Model:      model,
		Dimensions: dimensions,
		MaxTokens:  maxTokens,
		Client:     &http.Client{Timeout: 30 * time.Second},
	}
	c.tokenizer = c
	return c
}

func (c *HTTPClient) endpoint(path string) string { return strings.TrimRight(c.BaseURL, "/") + path }

func (c *HTTPClient) Tokenize(ctx context.Context, text string) ([]int, error) {
	body, err := json.Marshal(tokenizeRequest{Content: text})
	if err != nil {
		return nil, err
	}
	var response tokenizeResponse
	if err := c.postJSON(ctx, "/tokenize", body, &response); err != nil {
		return nil, fmt.Errorf("tokenize endpoint: %w", err)
	}
	return response.Tokens, nil
}

func (c *HTTPClient) Detokenize(ctx context.Context, tokens []int) (string, error) {
	body, err := json.Marshal(detokenizeRequest{Tokens: tokens})
	if err != nil {
		return "", err
	}
	var response detokenizeResponse
	if err := c.postJSON(ctx, "/detokenize", body, &response); err != nil {
		return "", fmt.Errorf("detokenize endpoint: %w", err)
	}
	return response.Content, nil
}

// ValidateTokenizer proves that both llama.cpp tokenizer endpoints are usable
// and mutually compatible before a worker can claim durable jobs.
func (c *HTTPClient) ValidateTokenizer(ctx context.Context) error {
	tokens, err := c.Tokenize(ctx, "atheros-search tokenizer readiness")
	if err != nil {
		return fmt.Errorf("validate llama.cpp /tokenize: %w", err)
	}
	if len(tokens) == 0 {
		return errors.New("validate llama.cpp /tokenize: returned no tokens")
	}
	text, err := c.Detokenize(ctx, tokens)
	if err != nil {
		return fmt.Errorf("validate llama.cpp /detokenize: %w", err)
	}
	if text == "" {
		return errors.New("validate llama.cpp /detokenize: returned empty content")
	}
	verified, err := c.Tokenize(ctx, text)
	if err != nil {
		return fmt.Errorf("validate llama.cpp tokenizer round trip: %w", err)
	}
	if len(verified) != len(tokens) {
		return fmt.Errorf("validate llama.cpp tokenizer round trip: got %d tokens after detokenize, expected %d", len(verified), len(tokens))
	}
	return nil
}

func (c *HTTPClient) Embed(ctx context.Context, texts []string, _ Kind) ([][]float32, error) {
	if c.BaseURL == "" {
		return nil, errors.New("embedding backend URL is empty")
	}
	offsets := make([]int, len(texts)+1)
	inputs := make([]TokenChunk, 0, len(texts))
	for i, text := range texts {
		chunks, err := ChunkText(ctx, c.tokenizer, text)
		if err != nil {
			return nil, err
		}
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

func (c *HTTPClient) embedInputs(ctx context.Context, inputs []TokenChunk) ([][]float32, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	var batches [][]TokenChunk
	for start := 0; start < len(inputs); {
		count, end := 0, start
		for end < len(inputs) {
			if inputs[end].TokenCount > RequestTokenLimit {
				return nil, fmt.Errorf("embedding chunk has %d content tokens, limit is %d", inputs[end].TokenCount, RequestTokenLimit)
			}
			if end > start && count+inputs[end].TokenCount > RequestTokenLimit {
				break
			}
			count += inputs[end].TokenCount
			end++
		}
		batches = append(batches, inputs[start:end])
		start = end
	}
	results := make([][][]float32, len(batches))
	jobs := make(chan int)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				texts := make([]string, len(batches[index]))
				for i := range batches[index] {
					texts[i] = batches[index][i].Text
				}
				vectors, err := c.embedOnce(ctx, texts)
				if err != nil {
					select {
					case errCh <- err:
						cancel()
					default:
					}
					return
				}
				results[index] = vectors
			}
		}()
	}
	for i := range batches {
		select {
		case jobs <- i:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errCh:
		return nil, err
	default:
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vectors := make([][]float32, 0, len(inputs))
	for _, batch := range results {
		vectors = append(vectors, batch...)
	}
	return vectors, nil
}

func (c *HTTPClient) embedOnce(ctx context.Context, inputs []string) ([][]float32, error) {
	body, err := json.Marshal(embeddingsRequest{Model: c.Model, Input: inputs})
	if err != nil {
		return nil, err
	}
	var parsed embeddingsResponse
	if err := c.postJSON(ctx, "/v1/embeddings", body, &parsed); err != nil {
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

func (c *HTTPClient) postJSON(ctx context.Context, path string, body []byte, output any) error {
	if c.BaseURL == "" {
		return errors.New("embedding backend URL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return &BackendUnavailableError{Cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return &BackendUnavailableError{Cause: fmt.Errorf("embedding backend returned %s; read response body: %w", resp.Status, readErr)}
		}
		err := fmt.Errorf("embedding backend returned %s", resp.Status)
		if message := responseErrorText(responseBody); message != "" {
			err = fmt.Errorf("embedding backend returned %s: %s", resp.Status, message)
		}
		if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests {
			return &BackendUnavailableError{Cause: err}
		}
		return err
	}
	if err := json.NewDecoder(resp.Body).Decode(output); err != nil {
		return &BackendUnavailableError{Cause: err}
	}
	return nil
}

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
	for i := range mean {
		mean[i] /= float32(len(chunkVectors))
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
			if encoded, err := json.Marshal(value); err == nil {
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
	_, err := c.Embed(ctx, []string{"kind: event\nquery: healthcheck"}, KindEvent)
	return err
}
