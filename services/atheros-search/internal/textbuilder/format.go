package textbuilder

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const MaxTokens = 384
const OverheadTokens = 16
const ContentTokenBudget = MaxTokens - OverheadTokens

func AppendValue(lines *[]string, field, value string) {
	value = strings.TrimSpace(value)
	if IsEmptyValue(value) {
		return
	}
	*lines = append(*lines, field+": "+value)
}

func IsEmptyValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "none", "null", "unknown":
		return true
	default:
		return false
	}
}

func NormalizeWPSName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	if s == "" {
		return ""
	}
	digitEnd := 0
	for digitEnd < len(s) && s[digitEnd] >= '0' && s[digitEnd] <= '9' {
		digitEnd++
	}
	if digitEnd > 0 {
		rest := s[digitEnd:]
		switch {
		case strings.HasPrefix(rest, "\""), strings.HasPrefix(rest, "'"):
			s = strings.TrimSpace(rest[1:])
		case strings.HasPrefix(rest, " inch"):
			s = strings.TrimSpace(rest[5:])
		case strings.HasPrefix(rest, "-inch"):
			s = strings.TrimSpace(rest[5:])
		}
	}
	for _, suffix := range []string{
		" smart television",
		" full hd tv",
		" smart tv",
		" android tv",
		" roku tv",
		" led tv",
		" lcd tv",
		" 4k tv",
		" hd tv",
		" television",
		" monitor",
		" display",
		" uhd tv",
		" tv",
	} {
		if strings.HasSuffix(s, suffix) {
			s = strings.TrimSpace(s[:len(s)-len(suffix)])
			break
		}
	}
	return strings.Join(strings.Fields(s), " ")
}

func TemporalContextLines(t time.Time) []string {
	weekday := t.Weekday()
	isWeekend := weekday == time.Saturday || weekday == time.Sunday
	isBusinessHours := !isWeekend && t.Hour() >= 9 && t.Hour() < 17
	return []string{
		fmt.Sprintf("hour_of_day: %d", t.Hour()),
		"day_of_week: " + weekday.String(),
		fmt.Sprintf("is_weekend: %t", isWeekend),
		fmt.Sprintf("is_business_hours: %t", isBusinessHours),
	}
}

func ClampText(text string, maxWords int) string {
	if countWords(text) <= maxWords {
		return text
	}
	return truncateByLines(text, maxWords, "...")
}

func TruncateTokenSequence(tokens string, maxWords int) string {
	wordCount := countWords(tokens)
	if wordCount <= maxWords {
		return tokens
	}
	truncated := strings.Join(firstWords(tokens, maxWords), " ")
	return truncated + fmt.Sprintf(" (+%d truncated)", wordCount-maxWords)
}

func TruncateWords(s string, maxWords int) string {
	if countWords(s) <= maxWords {
		return s
	}
	return strings.Join(firstWords(s, maxWords), " ") + "..."
}

func NormalizeJSON(v any) string {
	if v == nil {
		return ""
	}
	switch value := v.(type) {
	case string:
		var parsed any
		if err := json.Unmarshal([]byte(value), &parsed); err == nil {
			return NormalizeJSON(parsed)
		}
		return value
	case []byte:
		return NormalizeJSON(string(value))
	case []any:
		items := make([]string, 0, len(value))
		for _, item := range value {
			encoded, err := json.Marshal(item)
			if err != nil {
				continue
			}
			items = append(items, string(encoded))
		}
		sort.Strings(items)
		encoded, err := json.Marshal(items)
		if err != nil {
			return ""
		}
		return string(encoded)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}
		return string(encoded)
	}
}

func EventsPerMinute(count int64, start, end *time.Time) float64 {
	if start == nil || end == nil || !end.After(*start) {
		return 0
	}
	minutes := end.Sub(*start).Minutes()
	if minutes <= 0 {
		return 0
	}
	return float64(count) / minutes
}

func wordBudget(tokenBudget int) int {
	return tokenBudget / 3
}

func clampDefault(text string) string {
	return ClampText(text, wordBudget(MaxTokens))
}

func prebuiltKindText(kind, text string, observed *time.Time) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	lines := []string{"kind: " + kind}
	if observed != nil {
		lines = append(lines, TemporalContextLines(*observed)...)
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "kind:") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func optionalTime(valid bool, value time.Time) *time.Time {
	if !valid {
		return nil
	}
	return &value
}

func countWords(s string) int {
	return len(strings.Fields(s))
}

func firstWords(s string, maxWords int) []string {
	if maxWords <= 0 {
		return nil
	}
	words := strings.Fields(s)
	if len(words) <= maxWords {
		return words
	}
	return words[:maxWords]
}

func truncateByLines(text string, maxWords int, suffix string) string {
	if maxWords <= 0 {
		return suffix
	}
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	remaining := maxWords
	for _, line := range lines {
		words := strings.Fields(line)
		if len(words) == 0 {
			out = append(out, line)
			continue
		}
		if len(words) > remaining {
			if remaining > 0 {
				out = append(out, strings.Join(words[:remaining], " ")+suffix)
			} else if len(out) > 0 {
				out[len(out)-1] += suffix
			} else {
				out = append(out, suffix)
			}
			return strings.Join(out, "\n")
		}
		out = append(out, line)
		remaining -= len(words)
		if remaining == 0 && hasLaterWords(lines[len(out):]) {
			out[len(out)-1] += suffix
			return strings.Join(out, "\n")
		}
	}
	return strings.Join(out, "\n")
}

func hasLaterWords(lines []string) bool {
	for _, line := range lines {
		if len(strings.Fields(line)) > 0 {
			return true
		}
	}
	return false
}
