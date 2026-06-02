package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
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
	Client     *http.Client
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

func NewHTTPClient(baseURL, model string, dimensions int) *HTTPClient {
	return &HTTPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Model:      model,
		Dimensions: dimensions,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *HTTPClient) Embed(ctx context.Context, texts []string, _ Kind) ([][]float32, error) {
	if c.BaseURL == "" {
		return nil, errors.New("embedding backend URL is empty")
	}
	body, err := json.Marshal(embeddingsRequest{Model: c.Model, Input: texts})
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
	if len(vectors) != len(texts) {
		return nil, fmt.Errorf("embedding backend returned %d vectors for %d texts", len(vectors), len(texts))
	}
	for i, vec := range vectors {
		if len(vec) != c.Dimensions {
			return nil, fmt.Errorf("embedding %d has %d dimensions, expected %d", i, len(vec), c.Dimensions)
		}
	}
	return vectors, nil
}

func (c *HTTPClient) Health(ctx context.Context) error {
	if c.BaseURL == "" {
		return errors.New("embedding backend URL is empty")
	}
	_, err := c.Embed(ctx, []string{"kind: event\nquery: healthcheck"}, KindEvent)
	return err
}
