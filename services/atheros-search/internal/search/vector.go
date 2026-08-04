package search

import (
	"strconv"
	"strings"
)

func VectorLiteral(v []float32) string {
	var b strings.Builder
	b.Grow(len(v) * 10)
	b.WriteByte('[')
	for i, item := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(item), 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}
