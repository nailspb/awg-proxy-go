package awg

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Константы протокола Noise IKpsk2, на котором построен handshake WireGuard.
const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

func newBlake2s() hash.Hash { h, _ := blake2s.New256(nil); return h }

// hashAll = BLAKE2s-256(part0 || part1 || ...).
func hashAll(parts ...[]byte) [32]byte {
	h := newBlake2s()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func hmacBlake(key, data []byte) [32]byte {
	m := hmac.New(newBlake2s, key)
	m.Write(data)
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// kdf1 = HKDF на один выход (mixKey в WireGuard).
func kdf1(key, input []byte) [32]byte {
	prk := hmacBlake(key, input)
	return hmacBlake(prk[:], []byte{0x1})
}

// kdf2 = HKDF на два выхода; возвращает (chainKey, ключ AEAD).
func kdf2(key, input []byte) (t1, t2 [32]byte) {
	prk := hmacBlake(key, input)
	t1 = hmacBlake(prk[:], []byte{0x1})
	in2 := append(append(make([]byte, 0, 33), t1[:]...), 0x2)
	t2 = hmacBlake(prk[:], in2)
	return
}

// ClientPubFromInit извлекает статический публичный ключ клиента из handshake-init,
// расшифровывая поле encrypted_static приватным ключом сервера (responder).
// init — чистое WireGuard-сообщение типа 1 (junk/обфускация уже снята).
// serverPub/serverPriv — ключи WG-интерфейса роутера. ok=false, если не вышло
// (короткий пакет, не тот ключ, повреждённое поле) — вызывающий откатится на burst.
func ClientPubFromInit(init []byte, serverPriv, serverPub [32]byte) (pub [32]byte, ok bool) {
	// init: type(4)+sender(4)+ephemeral(32)+encrypted_static(48)+...
	if len(init) < 88 {
		return pub, false
	}
	ephemeral := init[8:40]
	encStatic := init[40:88]

	// Воспроизводим хеш/чейн-цепочку Noise со стороны получателя.
	chainKey := blake2s.Sum256([]byte(noiseConstruction))
	h := hashAll(chainKey[:], []byte(wgIdentifier))
	h = hashAll(h[:], serverPub[:])
	h = hashAll(h[:], ephemeral)
	chainKey = kdf1(chainKey[:], ephemeral)

	ss, err := curve25519.X25519(serverPriv[:], ephemeral)
	if err != nil {
		return pub, false
	}
	_, key := kdf2(chainKey[:], ss)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return pub, false
	}
	var nonce [12]byte // counter 0
	out, err := aead.Open(nil, nonce[:], encStatic, h[:])
	if err != nil || len(out) != 32 {
		return pub, false
	}
	copy(pub[:], out)
	return pub, true
}
