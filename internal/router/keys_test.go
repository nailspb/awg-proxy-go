package router

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64key(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestParsePubKey(t *testing.T) {
	t.Parallel()

	t.Run("valid with whitespace", func(t *testing.T) {
		t.Parallel()
		k, err := parsePubKey("  " + b64key(7) + "\r\n")
		require.NoError(t, err)
		assert.Equal(t, byte(7), k[0])
		assert.Equal(t, byte(7), k[31])
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, err := parsePubKey("   ")
		assert.Error(t, err)
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Parallel()
		_, err := parsePubKey(base64.StdEncoding.EncodeToString([]byte("short")))
		assert.Error(t, err)
	})
}
