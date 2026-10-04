package binapi

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestLengthRoundtrip(t *testing.T) {
	cases := []int{0, 1, 0x7F, 0x80, 0x123, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0x0FFFFFFF, 0x10000000, 0x7FFFFFFF}
	for _, n := range cases {
		var buf bytes.Buffer
		if err := writeLength(&buf, n); err != nil {
			t.Fatalf("write %d: %v", n, err)
		}
		got, err := readLength(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("read %d: %v", n, err)
		}
		if got != n {
			t.Fatalf("roundtrip mismatch: want %d got %d", n, got)
		}
	}
}

func TestWordRoundtrip(t *testing.T) {
	words := []string{"", "/login", "=name=admin", "=password=", strings.Repeat("a", 200), strings.Repeat("b", 5000)}
	var buf bytes.Buffer
	for _, w := range words {
		if err := writeWord(&buf, w); err != nil {
			t.Fatalf("write %q: %v", w, err)
		}
	}
	r := bufio.NewReader(&buf)
	for i, want := range words {
		got, err := readWord(r)
		if err != nil {
			t.Fatalf("read[%d]: %v", i, err)
		}
		if got != want {
			t.Fatalf("read[%d]: want %q got %q", i, want, got)
		}
	}
}
