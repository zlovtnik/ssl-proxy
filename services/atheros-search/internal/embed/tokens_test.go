package embed

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// vocabTokenizer is a deterministic tokenizer/detokenizer mock. Every word
// maps to one stable token id, so detokenizing an exact token range rebuilds
// exactly the words in that range.
type vocabTokenizer struct {
	ids   map[string]int
	words map[int]string
	next  int
}

func newVocabTokenizer() *vocabTokenizer {
	return &vocabTokenizer{ids: make(map[string]int), words: make(map[int]string)}
}

func (t *vocabTokenizer) Tokenize(_ context.Context, text string) ([]int, error) {
	tokens := make([]int, 0, len(text)/4)
	for _, word := range strings.Fields(text) {
		id, ok := t.ids[word]
		if !ok {
			t.next++
			id = t.next
			t.ids[word] = id
			t.words[id] = word
		}
		tokens = append(tokens, id)
	}
	return tokens, nil
}

func (t *vocabTokenizer) Detokenize(_ context.Context, tokens []int) (string, error) {
	words := make([]string, len(tokens))
	for i, id := range tokens {
		word, ok := t.words[id]
		if !ok {
			return "", fmt.Errorf("unknown token id %d", id)
		}
		words[i] = word
	}
	return strings.Join(words, " "), nil
}

func syntheticSequenceText(tokenCount int) string {
	words := make([]string, tokenCount)
	for i := range words {
		words[i] = fmt.Sprintf("tok%06d", i)
	}
	return strings.Join(words, " ")
}

func TestChunkTextSplitsExactTokenRanges(t *testing.T) {
	tokenizer := newVocabTokenizer()
	text := syntheticSequenceText(1000)
	chunks, err := ChunkText(context.Background(), tokenizer, text)
	if err != nil {
		t.Fatalf("ChunkText returned error: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks of 480/480/40, got %d", len(chunks))
	}
	wantCounts := []int{480, 480, 40}
	for i, chunk := range chunks {
		if chunk.TokenCount != wantCounts[i] {
			t.Fatalf("chunk %d has %d tokens, want %d", i, chunk.TokenCount, wantCounts[i])
		}
		if got := len(strings.Fields(chunk.Text)); got != chunk.TokenCount {
			t.Fatalf("chunk %d detokenized to %d words, TokenCount is %d", i, got, chunk.TokenCount)
		}
	}
	var rebuilt []string
	for _, chunk := range chunks {
		rebuilt = append(rebuilt, strings.Fields(chunk.Text)...)
	}
	original := strings.Fields(text)
	if len(rebuilt) != len(original) {
		t.Fatalf("chunking lost tokens: rebuilt %d, original %d", len(rebuilt), len(original))
	}
	for i := range original {
		if rebuilt[i] != original[i] {
			t.Fatalf("rebuilt token %d = %q, want %q (order or range mismatch)", i, rebuilt[i], original[i])
		}
	}
}

// The retired heuristic dropped long sequence sources and recovery work found
// sequences larger than 173,443 tokens. Chunking must cover every token of a
// synthetic sequence beyond that size without exceeding the model context.
func TestChunkTextCoversSequenceBeyondLegacyLimit(t *testing.T) {
	const tokenCount = 180001
	tokenizer := newVocabTokenizer()
	chunks, err := ChunkText(context.Background(), tokenizer, syntheticSequenceText(tokenCount))
	if err != nil {
		t.Fatalf("ChunkText returned error: %v", err)
	}
	full := tokenCount / ChunkTokenLimit
	remainder := tokenCount % ChunkTokenLimit
	wantChunks := full
	if remainder > 0 {
		wantChunks++
	}
	if len(chunks) != wantChunks {
		t.Fatalf("expected %d chunks, got %d", wantChunks, len(chunks))
	}
	covered := 0
	for i, chunk := range chunks {
		if chunk.TokenCount > ChunkTokenLimit {
			t.Fatalf("chunk %d has %d tokens, limit is %d", i, chunk.TokenCount, ChunkTokenLimit)
		}
		want := ChunkTokenLimit
		if i == len(chunks)-1 && remainder > 0 {
			want = remainder
		}
		if chunk.TokenCount != want {
			t.Fatalf("chunk %d has %d tokens, want %d", i, chunk.TokenCount, want)
		}
		covered += chunk.TokenCount
	}
	if covered != tokenCount {
		t.Fatalf("chunks cover %d tokens, sequence has %d", covered, tokenCount)
	}
}
