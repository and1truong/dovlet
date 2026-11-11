package dovlet

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testPassword = "test-only-password-123"

var unicodeText = []byte("Xin chào Việt Nam! 🍎\n<script>alert(1)</script>\n" + strings.Repeat("hello", 10000))

func white(w, h int) *image.RGBA {
	m := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range m.Pix {
		m.Pix[i] = 255
	}
	return m
}

func px(m *image.RGBA) pixels { return pixels{m.Pix, m.Stride, m.Rect.Dx(), m.Rect.Dy()} }

func TestZipRoundTrip(t *testing.T) {
	archive, err := SealZip(unicodeText, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenZip(archive, testPassword)
	if err != nil || !bytes.Equal(got, unicodeText) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := OpenZip(archive, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	// Flip one bit in every position of the encrypted payload region.
	for i := 60; i < len(archive)-100; i += 97 {
		tampered := bytes.Clone(archive)
		tampered[i] ^= 1
		if got, err := OpenZip(tampered, testPassword); err == nil && !bytes.Equal(got, unicodeText) {
			t.Fatalf("tampering at %d produced different plaintext", i)
		}
	}
	tampered := bytes.Clone(archive)
	tampered[100] ^= 1
	if _, err := OpenZip(tampered, testPassword); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestStego(t *testing.T) {
	archive, _ := SealZip(unicodeText, testPassword)
	img := white(1200, 1200)
	if err := embed(px(img), archive); err != nil {
		t.Fatal(err)
	}
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] != 255 {
			t.Fatal("alpha changed")
		}
	}
	got, err := extract(px(img))
	if err != nil || !bytes.Equal(got, archive) {
		t.Fatalf("extract: %v", err)
	}
	if _, err := extract(px(white(1200, 1200))); !errors.Is(err, ErrNoMessage) {
		t.Fatalf("missing header: %v", err)
	}
	if err := embed(px(white(1, 1)), archive); !errors.Is(err, ErrCoverTooSmall) {
		t.Fatalf("capacity: %v", err)
	}
	// A forged length must be rejected rather than read past capacity.
	p := px(img)
	for bit := 64; bit < 96; bit++ {
		p.pix[p.offset(bit)] |= 1
	}
	if _, err := extract(p); !errors.Is(err, ErrBadPayload) {
		t.Fatalf("forged length: %v", err)
	}
}

func TestEncodeDecode(t *testing.T) {
	res, err := Encode(unicodeText, testPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Width != 1200 || res.Height != 1200 {
		t.Fatalf("default cover is %dx%d", res.Width, res.Height)
	}
	text, _, err := Decode(res.PNG, testPassword)
	if err != nil || !bytes.Equal(text, unicodeText) {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := Decode(res.PNG, "wrong-password-xyz"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	for _, c := range []struct {
		text, pw string
	}{{"", testPassword}, {"hi", "short"}, {"\xff\xfe", testPassword}, {strings.Repeat("a", MaxTextBytes+1), testPassword}} {
		if _, err := Encode([]byte(c.text), c.pw, nil); err == nil {
			t.Fatalf("accepted invalid input %.10q/%q", c.text, c.pw)
		}
	}
	// 12 code points, more bytes: allowed, like Array.from(password).length.
	if _, err := Encode([]byte("x"), "ááááááááááá1", nil); err != nil {
		t.Fatal(err)
	}
}

func TestCustomCover(t *testing.T) {
	// Translucent, oversized cover: flattened on white and scaled to 2000 px.
	src := image.NewNRGBA(image.Rect(0, 0, 3000, 1500))
	for i := range src.Pix {
		src.Pix[i] = uint8(i)
	}
	var buf bytes.Buffer
	png.Encode(&buf, src)
	res, err := Encode([]byte("custom cover"), testPassword, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if res.Width != 2000 || res.Height != 1000 {
		t.Fatalf("scaled to %dx%d", res.Width, res.Height)
	}
	out, _ := png.Decode(bytes.NewReader(res.PNG))
	if !out.(interface{ Opaque() bool }).Opaque() {
		t.Fatal("cover was not flattened")
	}

	// Tiny cover cannot hold the payload.
	buf.Reset()
	png.Encode(&buf, white(10, 10))
	if _, err := Encode([]byte("x"), testPassword, buf.Bytes()); !errors.Is(err, ErrCoverTooSmall) {
		t.Fatalf("tiny cover: %v", err)
	}
}

func TestOversizedImageRejected(t *testing.T) {
	// A PNG header claiming 5000×5000 is refused before decoding pixels.
	var buf bytes.Buffer
	png.Encode(&buf, image.NewGray(image.Rect(0, 0, 5000, 5000)))
	if _, _, err := Decode(buf.Bytes(), testPassword); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
}

func TestEXIFOrientation(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 40, 20))
	for y := range 20 {
		for x := range 40 {
			src.Set(x, y, color.RGBA{uint8(x * 6), uint8(y * 12), 0, 255})
		}
	}
	var buf bytes.Buffer
	jpeg.Encode(&buf, src, &jpeg.Options{Quality: 100})
	// Insert an APP1 Exif segment with orientation 6 (rotate 90° clockwise).
	exif := []byte("Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08\x00\x01\x01\x12\x00\x03\x00\x00\x00\x01\x00\x06\x00\x00\x00\x00\x00\x00")
	seg := append([]byte{0xFF, 0xE1, 0, byte(len(exif) + 2)}, exif...)
	data := append(append([]byte{0xFF, 0xD8}, seg...), buf.Bytes()[2:]...)
	if o := exifOrientation(data); o != 6 {
		t.Fatalf("orientation %d", o)
	}
	m, err := renderCover(data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Rect.Dx() != 20 || m.Rect.Dy() != 40 {
		t.Fatalf("not rotated: %v", m.Rect)
	}
	// Top-left of the rotated image is the original bottom-left (dark red, bright green).
	if c := m.RGBAAt(0, 0); c.G < 150 || c.R > 60 {
		t.Fatalf("wrong rotation, top-left = %v", c)
	}
}

// TestWebInterop runs the web app's JavaScript (zip.js + embed/extract/unzip)
// against this implementation in both directions. Set DOVLET_WEB_HTML to the
// web app's index.html to enable it.
func TestWebInterop(t *testing.T) {
	html := os.Getenv("DOVLET_WEB_HTML")
	if html == "" {
		t.Skip("DOVLET_WEB_HTML not set")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not found")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("node", append([]string{"testdata/interop.cjs", html}, args...)...)
		cmd.Env = append(os.Environ(), "PW="+testPassword)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("node %v: %v\n%s", args, err, out)
		}
	}

	t.Run("web to cli", func(t *testing.T) {
		msg, rgba := filepath.Join(dir, "msg.txt"), filepath.Join(dir, "web.rgba")
		os.WriteFile(msg, unicodeText, 0o600)
		run("embed", "1200", "1200", msg, rgba)
		raw, _ := os.ReadFile(rgba)
		img := &image.NRGBA{Pix: raw, Stride: 1200 * 4, Rect: image.Rect(0, 0, 1200, 1200)}
		var buf bytes.Buffer
		png.Encode(&buf, img)
		text, _, err := Decode(buf.Bytes(), testPassword)
		if err != nil || !bytes.Equal(text, unicodeText) {
			t.Fatalf("decode web image: %v", err)
		}
	})

	t.Run("cli to web", func(t *testing.T) {
		res, err := Encode(unicodeText, testPassword, nil)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := png.Decode(bytes.NewReader(res.PNG))
		p := toNRGBA(m)
		rgba, out := filepath.Join(dir, "cli.rgba"), filepath.Join(dir, "out.txt")
		os.WriteFile(rgba, p.pix, 0o600)
		run("extract", "1200", "1200", rgba, out)
		got, _ := os.ReadFile(out)
		if !bytes.Equal(got, unicodeText) {
			t.Fatal("web app could not read the CLI image")
		}
	})
}
