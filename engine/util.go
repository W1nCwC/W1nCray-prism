package engine

import (
	"crypto/rand"
	"encoding/hex"
)

func randomID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}
