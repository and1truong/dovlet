// Package dovlet hides a password-encrypted text message or ZIP file inside a PNG.
// The format is byte-compatible with the Dovlet web app
// (https://github.com/and1truong/dovlet).
package dovlet

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"math"
	"unicode/utf8"

	_ "image/jpeg"

	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	MaxTextBytes      = 500_000
	MaxZipBytes       = 1_400_000
	MaxImageBytes     = 25 << 20
	MaxImagePixels    = 16_000_000
	MinPasswordRunes  = 12
	maxCoverDimension = 2000
)

// Result describes an encoded image.
type Result struct {
	PNG           []byte
	Width, Height int
	ZipBytes      int
	Capacity      int
	// Entry is the name stored in the encrypted ZIP:
	// "message.txt" for text, the original filename for a ZIP file.
	Entry string
}

// ValidateMessage applies the web app's input rules.
func ValidateMessage(text []byte, password string) error {
	switch {
	case len(text) == 0:
		return errors.New("message is empty")
	case len(text) > MaxTextBytes:
		return fmt.Errorf("message is %d bytes; the limit is %d bytes of UTF-8", len(text), MaxTextBytes)
	case !utf8.Valid(text):
		return errors.New("message is not valid UTF-8 text")
	case utf8.RuneCountInString(password) < MinPasswordRunes:
		return fmt.Errorf("password must be at least %d characters", MinPasswordRunes)
	}
	return nil
}

// Encode encrypts text, embeds it into cover (nil means the built-in apple)
// and returns the PNG after verifying it decodes back to the same text.
func Encode(text []byte, password string, cover []byte) (*Result, error) {
	if err := ValidateMessage(text, password); err != nil {
		return nil, err
	}
	archive, err := SealZip(text, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	res, err := encodeArchive(archive, password, cover)
	if err != nil {
		return nil, err
	}
	res.Entry = entryName
	return res, nil
}

// EncodeFile encrypts a ZIP file, embeds it into cover (nil means the
// built-in apple) and returns the PNG after verifying it decodes back to
// the same file. The filename is kept as the ZIP entry name.
func EncodeFile(filename string, data []byte, password string, cover []byte) (*Result, error) {
	name, err := SafeZipName(filename)
	if err != nil {
		return nil, err
	}
	if err := ValidateZipFile(name, data); err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(password) < MinPasswordRunes {
		return nil, fmt.Errorf("password must be at least %d characters", MinPasswordRunes)
	}
	archive, err := SealZipFile(name, data, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	res, err := encodeArchive(archive, password, cover)
	if err != nil {
		return nil, err
	}
	res.Entry = name
	return res, nil
}

// encodeArchive embeds an already-sealed archive into cover and returns the
// PNG after verifying the exported image decodes back to the same archive.
func encodeArchive(archive []byte, password string, cover []byte) (*Result, error) {
	var canvas *image.RGBA
	var err error
	if cover == nil {
		canvas = Apple()
	} else if canvas, err = renderCover(cover); err != nil {
		return nil, err
	}
	b := canvas.Bounds()
	if err := embed(pixels{canvas.Pix, canvas.Stride, b.Dx(), b.Dy()}, archive); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := png.Encode(&out, canvas); err != nil {
		return nil, fmt.Errorf("encode PNG: %w", err)
	}
	_, got, err := Decode(out.Bytes(), password)
	if err != nil || !bytes.Equal(got, archive) {
		return nil, errors.New("self-check failed: the exported image did not decode to the original message")
	}
	return &Result{PNG: out.Bytes(), Width: b.Dx(), Height: b.Dy(), ZipBytes: len(archive), Capacity: Capacity(b.Dx(), b.Dy())}, nil
}

// Decode extracts and decrypts the message or ZIP file. It also returns the
// encrypted ZIP.
func Decode(img []byte, password string) (entry *Entry, archive []byte, err error) {
	m, err := loadImage(img)
	if err != nil {
		return nil, nil, err
	}
	if archive, err = extract(toNRGBA(m)); err != nil {
		return nil, nil, err
	}
	if entry, err = OpenZip(archive, password); err != nil {
		return nil, nil, ErrBadPassword
	}
	return entry, archive, nil
}

func loadImage(data []byte) (image.Image, error) {
	if len(data) > MaxImageBytes {
		return nil, fmt.Errorf("image is larger than %d MiB", MaxImageBytes>>20)
	}
	// Check dimensions before decoding so a small file cannot expand into a
	// huge allocation.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("unsupported or unreadable image: %w", err)
	}
	if int64(cfg.Width)*int64(cfg.Height) > MaxImagePixels {
		return nil, fmt.Errorf("image is too large: at most %d million pixels", MaxImagePixels/1_000_000)
	}
	m, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("unsupported or unreadable image: %w", err)
	}
	return m, nil
}

// renderCover flattens the image onto white, scales it down to at most
// 2000 px on its longest side and applies JPEG EXIF orientation, matching
// what the browser draws.
func renderCover(data []byte) (*image.RGBA, error) {
	src, err := loadImage(data)
	if err != nil {
		return nil, err
	}
	sb := src.Bounds()
	w, h := sb.Dx(), sb.Dy()
	ratio := math.Min(1, maxCoverDimension/float64(max(w, h)))
	dw := max(1, int(math.Round(float64(w)*ratio)))
	dh := max(1, int(math.Round(float64(h)*ratio)))
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	xdraw.Draw(dst, dst.Bounds(), image.White, image.Point{}, xdraw.Src)
	if dw == w && dh == h {
		xdraw.Draw(dst, dst.Bounds(), src, sb.Min, xdraw.Over)
	} else {
		xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, sb, xdraw.Over, nil)
	}
	return orient(dst, exifOrientation(data)), nil
}
