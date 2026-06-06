package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTruncateInputTextCutsAtLineBoundary(t *testing.T) {
	got := truncateInputText("line-one\nline-two-is-long\nline-three", 12)

	require.Equal(t, "line-one\n[truncated]", got)
}

func TestTruncateInputTextFallsBackToHardCut(t *testing.T) {
	got := truncateInputText("abcdefghijklmnopqrstuvwxyz", 10)

	require.Equal(t, "abcdefghijklmno\n[truncated]", got)
}

func TestContentSHA256Fallback(t *testing.T) {
	sum := sha256.Sum256([]byte("content"))

	require.Equal(t, hex.EncodeToString(sum[:]), contentSHA256("content"))
}
