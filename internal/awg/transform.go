package awg

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"

	"github.com/glebov/awg-proxy-go/internal/wg"
)

// Params — параметры обфускации AmneziaWG.
type Params struct {
	H1, H2, H3, H4 uint32
	S1, S2         int
	Jc, Jmin, Jmax int
}

// hFor возвращает магический заголовок AWG для типа сообщения WireGuard.
func (p Params) hFor(t uint32) uint32 {
	switch t {
	case wg.TypeInit:
		return p.H1
	case wg.TypeResponse:
		return p.H2
	case wg.TypeCookie:
		return p.H3
	default:
		return p.H4
	}
}

// prefixFor возвращает размер junk-префикса (S1/S2) для типа сообщения.
func (p Params) prefixFor(t uint32) int {
	switch t {
	case wg.TypeInit:
		return p.S1
	case wg.TypeResponse:
		return p.S2
	default:
		return 0
	}
}

// classify определяет тип входящего обфусцированного пакета по заголовку
// H1..H4 (с учётом junk-префикса для handshake) и возвращает смещение,
// с которого начинается сообщение WireGuard. ok=false означает junk-пакет.
func (p Params) classify(pkt []byte) (typ uint32, offset int, ok bool) {
	if len(pkt) < 4 {
		return 0, 0, false
	}
	switch binary.LittleEndian.Uint32(pkt[:4]) {
	case p.H4:
		return wg.TypeTransport, 0, true
	case p.H3:
		return wg.TypeCookie, 0, true
	}
	if len(pkt) >= p.S1+4 && binary.LittleEndian.Uint32(pkt[p.S1:p.S1+4]) == p.H1 {
		return wg.TypeInit, p.S1, true
	}
	if len(pkt) >= p.S2+4 && binary.LittleEndian.Uint32(pkt[p.S2:p.S2+4]) == p.H2 {
		return wg.TypeResponse, p.S2, true
	}
	return 0, 0, false
}

// Deobfuscate превращает входящий AWG-пакет в чистый WireGuard:
// снимает junk-префикс, ставит стандартный тип и пересчитывает MAC1
// (для handshake) ключом recipientPub — публичного ключа получателя
// чистого пакета (для init это ключ локального WG-сервера).
// Возвращает срез исходного буфера (мутирует pkt). ok=false — junk, дроп.
func (p Params) Deobfuscate(pkt []byte, recipientPub [32]byte) (plain []byte, typ uint32, ok bool) {
	typ, off, ok := p.classify(pkt)
	if !ok {
		return nil, 0, false
	}
	plain = pkt[off:]
	if len(plain) < 4 {
		return nil, 0, false
	}
	wg.SetType(plain, typ)
	if mo, has := wg.MAC1Offset(typ); has && len(plain) >= mo+wg.MAC1Size {
		mac := ComputeMAC1(recipientPub, plain[:mo])
		copy(plain[mo:mo+wg.MAC1Size], mac[:])
	}
	return plain, typ, true
}

// Obfuscate превращает чистый WireGuard-пакет в AWG: подменяет заголовок на
// H1..H4, пересчитывает MAC1 (для handshake) ключом recipientPub — публичного
// ключа получателя AWG-пакета (для response это ключ клиента) — и добавляет
// junk-префикс S1/S2. Возвращает новый буфер.
func (p Params) Obfuscate(plain []byte, recipientPub [32]byte) []byte {
	typ := wg.Type(plain)
	prefix := p.prefixFor(typ)
	out := make([]byte, prefix+len(plain))
	if prefix > 0 {
		crand.Read(out[:prefix])
	}
	copy(out[prefix:], plain)
	msg := out[prefix:]
	binary.LittleEndian.PutUint32(msg[:4], p.hFor(typ))
	if mo, has := wg.MAC1Offset(typ); has && len(msg) >= mo+wg.MAC1Size {
		mac := ComputeMAC1(recipientPub, msg[:mo])
		copy(msg[mo:mo+wg.MAC1Size], mac[:])
	}
	return out
}

// JunkPackets генерирует Jc мусорных пакетов случайной длины [Jmin,Jmax],
// которые initiator отправляет перед handshake init.
func (p Params) JunkPackets() [][]byte {
	if p.Jc <= 0 {
		return nil
	}
	out := make([][]byte, p.Jc)
	for i := range out {
		n := p.Jmin
		if p.Jmax > p.Jmin {
			n += mrand.IntN(p.Jmax - p.Jmin + 1)
		}
		b := make([]byte, n)
		crand.Read(b)
		out[i] = b
	}
	return out
}
