// Package binapi реализует бинарный протокол MikroTik API (port 8728 / api-ssl 8729).
//
// Формат: «предложения» из «слов», каждое слово — length-prefix + bytes.
// Длина пишется variable-length:
//
//	0x00..0x7F          → 1 байт  (length <= 127)
//	0x80..0xBF          → 2 байта (14 бит)
//	0xC0..0xDF          → 3 байта (21 бит)
//	0xE0..0xEF          → 4 байта (28 бит)
//	0xF0                → 5 байт  (32 бита, big-endian)
//
// Конец предложения — слово нулевой длины.
package binapi

import (
	"bufio"
	"fmt"
	"io"
)

// writeLength сериализует длину слова по правилам RouterOS API.
func writeLength(w io.Writer, n int) error {
	switch {
	case n < 0x80:
		return writeByte(w, byte(n))
	case n < 0x4000:
		n |= 0x8000
		return writeBytes(w, []byte{byte(n >> 8), byte(n)})
	case n < 0x200000:
		n |= 0xC00000
		return writeBytes(w, []byte{byte(n >> 16), byte(n >> 8), byte(n)})
	case n < 0x10000000:
		// Префикс 0xE0 пишем прямо в верхний байт — без OR с 0xE0000000,
		// которая не лезет в int на 32-бит платформах (armv7).
		return writeBytes(w, []byte{byte(n>>24) | 0xE0, byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		return writeBytes(w, []byte{0xF0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
}

// readLength десериализует длину следующего слова. EOF → io.EOF.
func readLength(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch {
	case b&0x80 == 0:
		return int(b), nil
	case b&0xC0 == 0x80:
		b2, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return (int(b&0x3F) << 8) | int(b2), nil
	case b&0xE0 == 0xC0:
		buf := make([]byte, 2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		return (int(b&0x1F) << 16) | (int(buf[0]) << 8) | int(buf[1]), nil
	case b&0xF0 == 0xE0:
		buf := make([]byte, 3)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		return (int(b&0x0F) << 24) | (int(buf[0]) << 16) | (int(buf[1]) << 8) | int(buf[2]), nil
	case b == 0xF0:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		return (int(buf[0]) << 24) | (int(buf[1]) << 16) | (int(buf[2]) << 8) | int(buf[3]), nil
	default:
		return 0, fmt.Errorf("binapi: invalid length byte 0x%02x", b)
	}
}

// writeWord пишет одно слово (length-prefix + raw bytes).
func writeWord(w io.Writer, s string) error {
	if err := writeLength(w, len(s)); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

// readWord читает одно слово. Пустое слово — конец предложения (возвращаем "", nil).
func readWord(r *bufio.Reader) (string, error) {
	n, err := readLength(r)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// writeByte/writeBytes — мелкие хелперы (io.Writer без необходимости в bufio).
func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func writeBytes(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
