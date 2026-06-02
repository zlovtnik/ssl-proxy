package search

import (
	"math"
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
		if math.IsNaN(float64(item)) || math.IsInf(float64(item), 0) {
			item = 0
		}
		b.WriteString(strconv.FormatFloat(float64(item), 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}
