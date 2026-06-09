// Package wg описывает формат сообщений WireGuard, нужный прокси:
// типы пакетов, индексы и смещение поля MAC1.
package wg

import "encoding/binary"

// Типы сообщений WireGuard (первые 4 байта пакета, little-endian).
const (
	TypeInit      uint32 = 1 // Handshake Initiation, 148 байт.
	TypeResponse  uint32 = 2 // Handshake Response, 92 байта.
	TypeCookie    uint32 = 3 // Cookie Reply, 64 байта.
	TypeTransport uint32 = 4 // Transport Data, >= 16 байт заголовка.
)

// Размеры handshake-сообщений.
const (
	SizeInit      = 148
	SizeResponse  = 92
	SizeCookie    = 64
	SizeTransport = 16 // минимальный заголовок transport-пакета
)

// Смещения поля MAC1 (16 байт) внутри handshake-сообщений.
const (
	mac1OffsetInit     = 116 // SizeInit - 32 (mac1 16 + mac2 16)
	mac1OffsetResponse = 60  // SizeResponse - 32
	MAC1Size           = 16
)

// Type возвращает тип сообщения из первых 4 байт.
func Type(pkt []byte) uint32 {
	if len(pkt) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(pkt[:4])
}

// SetType записывает стандартный тип WireGuard в первые 4 байта.
func SetType(pkt []byte, t uint32) {
	binary.LittleEndian.PutUint32(pkt[:4], t)
}

// SenderIndex — индекс отправителя (init и response: байты 4..8).
func SenderIndex(pkt []byte) uint32 {
	return binary.LittleEndian.Uint32(pkt[4:8])
}

// ReceiverIndex — индекс получателя.
// Для response он по смещению 8, для cookie и transport — по смещению 4.
func ReceiverIndex(pkt []byte) uint32 {
	switch Type(pkt) {
	case TypeResponse:
		return binary.LittleEndian.Uint32(pkt[8:12])
	case TypeCookie, TypeTransport:
		return binary.LittleEndian.Uint32(pkt[4:8])
	default:
		return 0
	}
}

// MAC1Offset возвращает смещение поля MAC1 для handshake-сообщения и true,
// либо false для сообщений без MAC1 (cookie, transport).
func MAC1Offset(t uint32) (int, bool) {
	switch t {
	case TypeInit:
		return mac1OffsetInit, true
	case TypeResponse:
		return mac1OffsetResponse, true
	default:
		return 0, false
	}
}
