package embed

import (
	"context"
	"fmt"
)

// DefaultMaxTokens is the llama.cpp model context. Chunks deliberately leave
// room for the backend's special tokens.
const DefaultMaxTokens = 512

// ChunkTokenLimit is the maximum tokenizer-counted content supplied for one
// source chunk. It is intentionally independent of character count.
const ChunkTokenLimit = 480

// RequestTokenLimit is the maximum tokenizer-counted content in one embedding
// request. llama.cpp applies its physical batch limit to this aggregate.
const RequestTokenLimit = 4096

type Tokenizer interface {
	Tokenize(context.Context, string) ([]int, error)
	Detokenize(context.Context, []int) (string, error)
}

// ChunkText uses the backend tokenizer rather than a heuristic, then rebuilds
// each exact token range through /detokenize. This preserves every source token
// and keeps a model input below the effective 512-token context.
func ChunkText(ctx context.Context, tokenizer Tokenizer, text string) ([]TokenChunk, error) {
	tokens, err := tokenizer.Tokenize(ctx, text)
	if err != nil {
		return nil, fmt.Errorf("tokenize embedding source: %w", err)
	}
	if len(tokens) == 0 {
		return []TokenChunk{{Text: text}}, nil
	}
	chunks := make([]TokenChunk, 0, (len(tokens)+ChunkTokenLimit-1)/ChunkTokenLimit)
	for start := 0; start < len(tokens); start += ChunkTokenLimit {
		end := start + ChunkTokenLimit
		if end > len(tokens) {
			end = len(tokens)
		}
		content, err := tokenizer.Detokenize(ctx, tokens[start:end])
		if err != nil {
			return nil, fmt.Errorf("detokenize embedding source tokens %d:%d: %w", start, end, err)
		}
		chunks = append(chunks, TokenChunk{Text: content, TokenCount: end - start})
	}
	return chunks, nil
}

type TokenChunk struct {
	Text       string
	TokenCount int
}
