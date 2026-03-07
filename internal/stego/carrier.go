// Copyright © 2026 Marcel Joachim Kloubert <marcel@kloubert.dev>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

package stego

import (
	"bytes"
	cryptoRand "crypto/rand"
	"embed"
	"fmt"
	"image"
	"image/png"
	mathRand "math/rand"
)

//go:embed images/*.png
var embeddedImages embed.FS

// supportedSizes lists the available pre-rendered image dimensions.
var supportedSizes = []int{16, 32, 64, 128, 256, 512, 1024}

const imageCount = 9

// carrierCache holds pre-decoded RGBA images keyed by dimension.
// Populated once at init(), never modified afterward.
var carrierCache map[int][]*image.RGBA

func init() {
	carrierCache = make(map[int][]*image.RGBA, len(supportedSizes))
	for _, size := range supportedSizes {
		variants := make([]*image.RGBA, imageCount)
		for i := 0; i < imageCount; i++ {
			path := fmt.Sprintf("images/image_%d_%dx%d.png", i+1, size, size)
			data, err := embeddedImages.ReadFile(path)
			if err != nil {
				panic("stego: failed to read embedded image for cache: " + err.Error())
			}

			img, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				panic("stego: failed to decode embedded image for cache: " + err.Error())
			}

			bounds := img.Bounds()
			rgba := image.NewRGBA(bounds)
			for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
				for x := bounds.Min.X; x < bounds.Max.X; x++ {
					rgba.Set(x, y, img.At(x, y))
				}
			}
			variants[i] = rgba
		}
		carrierCache[size] = variants
	}
}

// GenerateCarrier returns an RGBA carrier image of the given dimensions by
// cloning a randomly chosen pre-cached photo. The photos are real images
// (9 variants at 7 resolutions each), so the resulting PNGs look natural
// to DPI systems.
//
// The requested (width, height) is matched to the nearest supported square
// size (16, 32, 64, 128, 256, 512, 1024). A random image (1-9) is picked
// using crypto/rand.
func GenerateCarrier(width, height int) *image.RGBA {
	dim := width
	if height > dim {
		dim = height
	}
	size := bestSize(dim)

	idx := cryptoRandIntn(imageCount)
	src := carrierCache[size][idx]

	clone := image.NewRGBA(src.Bounds())
	copy(clone.Pix, src.Pix)
	return clone
}

// bestSize returns the smallest supported size that is >= dim.
func bestSize(dim int) int {
	for _, s := range supportedSizes {
		if s >= dim {
			return s
		}
	}
	return supportedSizes[len(supportedSizes)-1]
}

// cryptoRandIntn returns a cryptographically random int in [0, n).
func cryptoRandIntn(n int) int {
	var b [8]byte
	cryptoRand.Read(b[:])
	seed := int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 |
		int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7])<<56
	rng := mathRand.New(mathRand.NewSource(seed))
	return rng.Intn(n)
}
