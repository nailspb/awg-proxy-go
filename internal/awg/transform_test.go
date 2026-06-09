package awg

import (
	"encoding/binary"
	"testing"

	"github.com/glebov/awg-proxy-go/internal/wg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testParams — нетривиальные H/S, чтобы обфускация реально меняла пакет.
func testParams() Params {
	return Params{
		H1: 0xCAFEBABE, H2: 0xDEADBEEF, H3: 0x11112222, H4: 0x33334444,
		S1: 16, S2: 24,
		Jc: 3, Jmin: 40, Jmax: 70,
	}
}

func buildInit(pub [32]byte) []byte {
	pkt := make([]byte, wg.SizeInit)
	wg.SetType(pkt, wg.TypeInit)
	binary.LittleEndian.PutUint32(pkt[4:8], 0xAABBCCDD) // sender index
	for i := 12; i < 116; i++ {
		pkt[i] = byte(i)
	}
	mac := ComputeMAC1(pub, pkt[:116])
	copy(pkt[116:132], mac[:])
	return pkt
}

func TestRoundtrip(t *testing.T) {
	t.Parallel()
	p := testParams()
	pub := [32]byte{1, 2, 3, 4, 5}

	t.Run("init handshake", func(t *testing.T) {
		t.Parallel()
		orig := buildInit(pub)
		want := append([]byte(nil), orig...)

		obf := p.Obfuscate(append([]byte(nil), orig...), pub)
		require.Len(t, obf, p.S1+wg.SizeInit)
		assert.Equal(t, p.H1, binary.LittleEndian.Uint32(obf[p.S1:p.S1+4]))

		plain, typ, ok := p.Deobfuscate(obf, pub)
		require.True(t, ok)
		assert.Equal(t, wg.TypeInit, typ)
		assert.Equal(t, want, plain)
	})

	t.Run("transport without mac", func(t *testing.T) {
		t.Parallel()
		orig := make([]byte, 80)
		wg.SetType(orig, wg.TypeTransport)
		binary.LittleEndian.PutUint32(orig[4:8], 0x12345678) // receiver index
		for i := 8; i < 80; i++ {
			orig[i] = byte(i)
		}
		want := append([]byte(nil), orig...)

		obf := p.Obfuscate(append([]byte(nil), orig...), pub)
		require.Len(t, obf, 80) // транспорт без префикса
		assert.Equal(t, p.H4, binary.LittleEndian.Uint32(obf[:4]))

		plain, typ, ok := p.Deobfuscate(obf, pub)
		require.True(t, ok)
		assert.Equal(t, wg.TypeTransport, typ)
		assert.Equal(t, want, plain)
	})
}

func TestJunkDropped(t *testing.T) {
	t.Parallel()
	p := testParams()
	junk := make([]byte, 64)
	for i := range junk {
		junk[i] = 0xFF
	}
	_, _, ok := p.Deobfuscate(junk, [32]byte{})
	assert.False(t, ok)
}

func TestJunkPackets(t *testing.T) {
	t.Parallel()
	p := testParams()
	pkts := p.JunkPackets()
	require.Len(t, pkts, p.Jc)
	for _, b := range pkts {
		assert.GreaterOrEqual(t, len(b), p.Jmin)
		assert.LessOrEqual(t, len(b), p.Jmax)
	}
}

func TestComputeMAC1(t *testing.T) {
	t.Parallel()
	msg := []byte("the quick brown fox")

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		a := ComputeMAC1([32]byte{1}, msg)
		b := ComputeMAC1([32]byte{1}, msg)
		assert.Equal(t, a, b)
	})

	t.Run("key sensitive", func(t *testing.T) {
		t.Parallel()
		a := ComputeMAC1([32]byte{1}, msg)
		b := ComputeMAC1([32]byte{2}, msg)
		assert.NotEqual(t, a, b)
	})
}
