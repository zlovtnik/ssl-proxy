package embed

import (
	"fmt"
	"strings"
	"testing"
)

func TestEstimateTokensCountsSpecialCharacters(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"empty", "", 0},
		{"short run", "aaaa", 2},                        // ceil(4/3)
		{"ten run", "aaaaaaaaaa", 4},                    // ceil(10/3)
		{"mac address", "aa:bb:cc:dd:ee:ff", 11},        // 6 runs of 2 + 5 colons
		{"spaces skipped", "hello world", 4},            // ceil(5/3) + ceil(5/3)
		{"newline counts", "kind: event\nquery: x", 10}, // 5 + 1 + 2 + 1 + 1
		{"json punctuation", `{"a":1}`, 7},              // { " a " : 1 }
		{"non-ascii double counted", "caf\u00e9", 3},    // ceil(3/3) + 2
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EstimateTokens(tc.text); got != tc.want {
				t.Fatalf("EstimateTokens(%q) = %d, want %d", tc.text, got, tc.want)
			}
		})
	}
}

func TestChunkTextShortInputPassthrough(t *testing.T) {
	text := "kind: event\nsource_mac: aa:bb:cc:dd:ee:ff"
	chunks := ChunkText(text, DefaultMaxTokens)
	if len(chunks) != 1 || chunks[0] != text {
		t.Fatalf("short text must pass through unchanged, got %d chunks", len(chunks))
	}
}

func TestChunkTextRespectsTokenBudget(t *testing.T) {
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, fmt.Sprintf("field_%02d: sensor-1 aa:bb:cc:dd:ee:%02x", i, i))
	}
	text := strings.Join(lines, "\n")
	maxTokens := 64
	budget := chunkBudget(maxTokens)
	chunks := ChunkText(text, maxTokens)
	if len(chunks) < 2 {
		t.Fatalf("expected long text to be split, got %d chunks", len(chunks))
	}
	for i, chunk := range chunks {
		if got := EstimateTokens(chunk); got > budget {
			t.Fatalf("chunk %d uses %d tokens, budget is %d", i, got, budget)
		}
	}
	rejoined := strings.Join(chunks, "\n")
	for _, line := range lines {
		if !strings.Contains(rejoined, line) {
			t.Fatalf("chunking lost line %q", line)
		}
	}
}

func TestChunkTextHardSplitsOversizedWord(t *testing.T) {
	word := strings.Repeat("a", 500)
	chunks := ChunkText(word, 32)
	budget := chunkBudget(32)
	if len(chunks) < 2 {
		t.Fatalf("expected oversized word to be hard-split, got %d chunks", len(chunks))
	}
	if strings.Join(chunks, "") != word {
		t.Fatalf("hard split lost content")
	}
	for i, chunk := range chunks {
		if got := EstimateTokens(chunk); got > budget {
			t.Fatalf("chunk %d uses %d tokens, budget is %d", i, got, budget)
		}
	}
}

func TestChunkTextHardSplitsPunctuationHeavyWord(t *testing.T) {
	// Punctuation counts one token per character, so this line must be
	// split by rune even though it is short in bytes.
	word := strings.Repeat("!?", 100)
	chunks := ChunkText(word, 32)
	budget := chunkBudget(32)
	if strings.Join(chunks, "") != word {
		t.Fatalf("hard split lost content")
	}
	for i, chunk := range chunks {
		if got := EstimateTokens(chunk); got > budget {
			t.Fatalf("chunk %d uses %d tokens, budget is %d", i, got, budget)
		}
	}
}
