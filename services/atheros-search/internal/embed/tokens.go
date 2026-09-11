package embed

import "strings"

// DefaultMaxTokens is the default per-input token budget used to split
// embedding texts. The llama.cpp embedding backend rejects any input larger
// than its model context (n_ctx=512 for the nomic-embed-text-v2-moe
// deployment), so texts are broken into chunks of at most this many
// estimated tokens before they are sent.
const DefaultMaxTokens = 512

// tokenOverhead is reserved from the configured budget so BOS/EOS special
// tokens and estimator error still fit inside the model context.
const tokenOverhead = 8

// minChunkTokens keeps pathological budgets workable instead of producing
// single-rune chunks.
const minChunkTokens = 16

// chunkBudget converts the configured max tokens into the budget applied to
// each chunk.
func chunkBudget(maxTokens int) int {
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}
	budget := maxTokens - tokenOverhead
	if budget < minChunkTokens {
		budget = minChunkTokens
	}
	return budget
}

// EstimateTokens returns a conservative upper-bound estimate of the number
// of tokens a BPE tokenizer produces for text. It deliberately over-counts:
//   - ASCII letters and digits are grouped into runs priced at one token per
//     three characters (real tokenizers average closer to four),
//   - every ASCII punctuation or symbol character is counted as its own
//     token. BPE usually splits punctuation off, and this corpus is dense
//     with MAC addresses, JSON, tags and "key: value" separators, so a
//     naive characters/4 estimate would badly under-count,
//   - every non-ASCII rune is counted as two tokens (some scripts tokenise
//     to more than one token per character),
//   - every newline counts as one token.
func EstimateTokens(text string) int {
	total := 0
	run := 0
	flush := func() {
		if run > 0 {
			total += (run + 2) / 3 // ceil(run/3)
			run = 0
		}
	}
	for _, r := range text {
		switch {
		case r == '\n' || r == '\r':
			flush()
			total++
		case r == ' ' || r == '\t':
			flush()
		case r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
			run++
		case r < 0x80:
			flush()
			total++ // ASCII punctuation/symbols are their own token
		default:
			flush()
			total += 2 // non-ASCII runes: conservatively 2 tokens each
		}
	}
	flush()
	return total
}

// ChunkText splits text into chunks whose estimated token count does not
// exceed maxTokens. Chunk boundaries prefer whole lines (the embedding text
// format is line-based "key: value" fields), then whole words, and only
// hard-splits by rune when a single word cannot fit the budget on its own.
// Rejoining the chunks with "\n" preserves all content, though whitespace
// inside hard-split word runs may be normalised to single spaces.
func ChunkText(text string, maxTokens int) []string {
	budget := chunkBudget(maxTokens)
	if EstimateTokens(text) <= budget {
		return []string{text}
	}
	var chunks []string
	current := ""
	for _, line := range strings.Split(text, "\n") {
		if current == "" {
			current = line
		} else if EstimateTokens(current+"\n"+line) <= budget {
			current += "\n" + line
		} else {
			chunks = append(chunks, current)
			current = line
		}
		if EstimateTokens(current) > budget {
			// A single line overflows the budget; split it on word
			// boundaries (and hard-split any oversized word).
			chunks = append(chunks, splitLine(current, budget)...)
			current = ""
		}
	}
	if current != "" {
		chunks = append(chunks, current)
	}
	return chunks
}

// splitLine packs whitespace-separated words into chunks within budget,
// falling back to hardSplitWord for a word that alone exceeds it.
func splitLine(line string, budget int) []string {
	words := strings.Fields(line)
	if len(words) == 0 {
		return []string{line}
	}
	var chunks []string
	current := ""
	for _, word := range words {
		if EstimateTokens(word) > budget {
			if current != "" {
				chunks = append(chunks, current)
				current = ""
			}
			chunks = append(chunks, hardSplitWord(word, budget)...)
			continue
		}
		if current == "" {
			current = word
			continue
		}
		if EstimateTokens(current+" "+word) <= budget {
			current += " " + word
		} else {
			chunks = append(chunks, current)
			current = word
		}
	}
	if current != "" {
		chunks = append(chunks, current)
	}
	return chunks
}

// hardSplitWord splits a single oversized word by runes into pieces within
// budget. Rune-wise appending works because EstimateTokens is monotonic in
// the characters appended.
func hardSplitWord(word string, budget int) []string {
	var chunks []string
	var current strings.Builder
	for _, r := range word {
		if EstimateTokens(current.String()+string(r)) > budget && current.Len() > 0 {
			chunks = append(chunks, current.String())
			current.Reset()
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		chunks = append(chunks, current.String())
	}
	return chunks
}
