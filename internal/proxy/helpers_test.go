package proxy

import (
	"encoding/json"
	"io"
	"testing"
)

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
