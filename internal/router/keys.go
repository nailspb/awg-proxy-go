package router

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair генерирует пару ключей WireGuard (base64), как `wg genkey`/`wg pubkey`.
// Приватный ключ нужен клиенту, публичный — заносится в пира на роутере.
func GenerateKeypair() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return "", "", err
	}
	// Clamp по спецификации curve25519.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	pubKey, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(pubKey), nil
}
