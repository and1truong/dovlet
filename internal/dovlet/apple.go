package dovlet

import (
	"image"
	"image/color"
	"image/draw"
	"math"

	"golang.org/x/image/vector"
)

const appleSize = 1200

// Apple renders the default 1200×1200 cover, the same illustration the web
// app draws on its canvas.
func Apple() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, appleSize, appleSize))
	draw.Draw(img, img.Bounds(), image.NewUniform(hex(0xf1efe3, 0xff)), image.Point{}, draw.Src)

	// Shadow.
	r := newPath()
	r.ellipse(600, 934, 246, 34)
	r.fill(img, image.NewUniform(hex(0xe1e1d1, 0xff)))

	// Body with a diagonal gradient.
	r = newPath()
	r.MoveTo(600, 388)
	r.CubeTo(318, 222, 218, 520, 348, 769)
	r.CubeTo(420, 936, 501, 931, 600, 890)
	r.CubeTo(695, 945, 815, 908, 868, 721)
	r.CubeTo(973, 435, 791, 280, 600, 388)
	r.ClosePath()
	r.fill(img, &linearGradient{
		x0: 350, y0: 300, x1: 830, y1: 900,
		stops: []gradientStop{{0, hex(0xee654b, 0xff)}, {0.5, hex(0xcb342b, 0xff)}, {1, hex(0x8d2425, 0xff)}},
	})

	// Stem.
	r = newPath()
	r.strokeQuad(603, 397, 584, 316, 637, 263, 29)
	r.fill(img, image.NewUniform(hex(0x644831, 0xff)))

	// Leaf.
	r = newPath()
	r.MoveTo(619, 336)
	r.CubeTo(632, 219, 765, 229, 790, 230)
	r.CubeTo(771, 337, 690, 367, 619, 336)
	r.ClosePath()
	r.fill(img, image.NewUniform(hex(0x527449, 0xff)))

	// Highlight.
	r = newPath()
	r.strokeQuad(429, 441, 352, 500, 377, 623, 23)
	r.fill(img, image.NewUniform(hex(0xffffff, 0x45)))
	return img
}

func hex(rgb uint32, a uint8) color.NRGBA {
	return color.NRGBA{uint8(rgb >> 16), uint8(rgb >> 8), uint8(rgb), a}
}

type path struct{ *vector.Rasterizer }

func newPath() path {
	r := vector.NewRasterizer(appleSize, appleSize)
	r.DrawOp = draw.Over
	return path{r}
}

func (p path) fill(dst draw.Image, src image.Image) {
	p.Draw(dst, dst.Bounds(), src, image.Point{})
}

// kappa places cubic control points to approximate a quarter ellipse.
const kappa = 0.5522847498

func (p path) ellipse(cx, cy, rx, ry float32) {
	kx, ky := rx*kappa, ry*kappa
	p.MoveTo(cx+rx, cy)
	p.CubeTo(cx+rx, cy+ky, cx+kx, cy+ry, cx, cy+ry)
	p.CubeTo(cx-kx, cy+ry, cx-rx, cy+ky, cx-rx, cy)
	p.CubeTo(cx-rx, cy-ky, cx-kx, cy-ry, cx, cy-ry)
	p.CubeTo(cx+kx, cy-ry, cx+rx, cy-ky, cx+rx, cy)
	p.ClosePath()
}

// strokeQuad approximates a round-capped stroke of a quadratic curve as a
// union of discs along it. All discs share one winding direction, so
// overlaps never cancel and translucent strokes stay uniform.
func (p path) strokeQuad(x0, y0, cx, cy, x1, y1, width float32) {
	const steps = 400
	r := width / 2
	for i := 0; i <= steps; i++ {
		t := float32(i) / steps
		u := 1 - t
		x := u*u*x0 + 2*u*t*cx + t*t*x1
		y := u*u*y0 + 2*u*t*cy + t*t*y1
		p.ellipse(x, y, r, r)
	}
}

type gradientStop struct {
	at float64
	c  color.NRGBA
}

// linearGradient interpolates straight-alpha sRGB like a canvas gradient.
type linearGradient struct {
	x0, y0, x1, y1 float64
	stops          []gradientStop
}

func (g *linearGradient) ColorModel() color.Model { return color.NRGBAModel }
func (g *linearGradient) Bounds() image.Rectangle {
	return image.Rect(-1e9, -1e9, 1e9, 1e9)
}

func (g *linearGradient) At(x, y int) color.Color {
	dx, dy := g.x1-g.x0, g.y1-g.y0
	t := ((float64(x)+0.5-g.x0)*dx + (float64(y)+0.5-g.y0)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	s := g.stops
	for i := 1; i < len(s); i++ {
		if t <= s[i].at {
			f := (t - s[i-1].at) / (s[i].at - s[i-1].at)
			lerp := func(a, b uint8) uint8 { return uint8(math.Round(float64(a) + (float64(b)-float64(a))*f)) }
			a, b := s[i-1].c, s[i].c
			return color.NRGBA{lerp(a.R, b.R), lerp(a.G, b.G), lerp(a.B, b.B), lerp(a.A, b.A)}
		}
	}
	return s[len(s)-1].c
}
