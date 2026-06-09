// Package awg реализует обфускацию AmneziaWG поверх WireGuard:
// подмену заголовков H1..H4, junk-префиксы S1/S2, junk-пакеты Jc и
// пересчёт MAC1 при конвертации между обфусцированным и чистым форматом.
package awg

import "golang.org/x/crypto/blake2s"

var labelMAC1 = []byte("mac1----")

// mac1Key = Blake2s-256(LABEL_MAC1 || pub) — ключ для keyed-MAC.
func mac1Key(pub [32]byte) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write(labelMAC1)
	h.Write(pub[:])
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// ComputeMAC1 считает поле mac1 сообщения WireGuard:
// MAC(HASH(LABEL_MAC1 || pub), msg) через keyed Blake2s-128,
// где pub — статический публичный ключ ПОЛУЧАТЕЛЯ сообщения.
func ComputeMAC1(pub [32]byte, msg []byte) [16]byte {
	key := mac1Key(pub)
	m, _ := blake2s.New128(key[:])
	m.Write(msg)
	var out [16]byte
	m.Sum(out[:0])
	return out
}
