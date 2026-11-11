package dovlet

import (
	"encoding/binary"
	"errors"
	"image"
)

// Payload layout: "APPLE001" | uint32 BE length | encrypted ZIP.
// Bits go one per R, G, B channel (alpha untouched), pixels in row-major
// order, most significant bit of each byte first.
var magic = []byte("APPLE001")

const headerLen = 12

var (
	ErrCoverTooSmall = errors.New("cover image is too small for this message; use the default cover or a larger image")
	ErrNoMessage     = errors.New("no Dovlet message found; the image may have been recompressed or edited")
	ErrBadPayload    = errors.New("image data is invalid or corrupted")
)

// pixels is an 8-bit, 4-channel buffer (RGBA or NRGBA layout).
type pixels struct {
	pix    []byte
	stride int
	w, h   int
}

func (p pixels) offset(bit int) int {
	i := bit / 3
	return (i/p.w)*p.stride + (i%p.w)*4 + bit%3
}

// Capacity returns the number of ZIP bytes a w×h image can carry.
func Capacity(w, h int) int {
	return max(0, w*h*3/8-headerLen)
}

func embed(p pixels, payload []byte) error {
	if len(payload) > Capacity(p.w, p.h) {
		return ErrCoverTooSmall
	}
	b := make([]byte, headerLen+len(payload))
	copy(b, magic)
	binary.BigEndian.PutUint32(b[8:], uint32(len(payload)))
	copy(b[headerLen:], payload)
	for k := range len(b) * 8 {
		o := p.offset(k)
		p.pix[o] = p.pix[o]&0xFE | (b[k>>3]>>(7-k%8))&1
	}
	return nil
}

func extract(p pixels) ([]byte, error) {
	capBytes := p.w * p.h * 3 / 8
	read := func(n int) []byte {
		b := make([]byte, n)
		for k := range n * 8 {
			b[k>>3] |= (p.pix[p.offset(k)] & 1) << (7 - k%8)
		}
		return b
	}
	if capBytes < headerLen {
		return nil, ErrNoMessage
	}
	h := read(headerLen)
	if string(h[:8]) != string(magic) {
		return nil, ErrNoMessage
	}
	n := int64(binary.BigEndian.Uint32(h[8:]))
	if n < 22 || n > int64(capBytes-headerLen) || n > MaxTextBytes+10000 {
		return nil, ErrBadPayload
	}
	return read(int(n) + headerLen)[headerLen:], nil
}

// toNRGBA returns the image's straight-alpha 8-bit pixels, which is what a
// browser canvas exposes through getImageData for an opaque image.
func toNRGBA(img image.Image) pixels {
	b := img.Bounds()
	switch m := img.(type) {
	case *image.NRGBA:
		return pixels{m.Pix[m.PixOffset(b.Min.X, b.Min.Y):], m.Stride, b.Dx(), b.Dy()}
	case *image.RGBA:
		if m.Opaque() {
			return pixels{m.Pix[m.PixOffset(b.Min.X, b.Min.Y):], m.Stride, b.Dx(), b.Dy()}
		}
	}
	out := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			out.Set(x-b.Min.X, y-b.Min.Y, img.At(x, y))
		}
	}
	return pixels{out.Pix, out.Stride, b.Dx(), b.Dy()}
}
