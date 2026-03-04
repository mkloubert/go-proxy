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
	"testing"
)

func TestGenerateCarrier_ReturnsCorrectDimensions(t *testing.T) {
	img := GenerateCarrier(256, 256)

	bounds := img.Bounds()
	if bounds.Dx() != 256 {
		t.Errorf("expected width 256, got %d", bounds.Dx())
	}
	if bounds.Dy() != 256 {
		t.Errorf("expected height 256, got %d", bounds.Dy())
	}
}

func TestGenerateCarrier_AllPixelsHaveFullAlpha(t *testing.T) {
	img := GenerateCarrier(256, 256)

	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := img.At(x, y).RGBA()
			if a != 65535 {
				t.Fatalf("pixel (%d, %d) has alpha %d, expected 65535", x, y, a)
			}
		}
	}
}

func TestGenerateCarrier_AllSizesAvailable(t *testing.T) {
	for _, size := range supportedSizes {
		img := GenerateCarrier(size, size)
		bounds := img.Bounds()
		if bounds.Dx() != size || bounds.Dy() != size {
			t.Errorf("size %d: expected %dx%d, got %dx%d", size, size, size, bounds.Dx(), bounds.Dy())
		}
	}
}

func TestGenerateCarrier_UpsizesToNearestSupported(t *testing.T) {
	img := GenerateCarrier(100, 100)
	bounds := img.Bounds()
	if bounds.Dx() != 128 || bounds.Dy() != 128 {
		t.Errorf("expected 128x128 for input 100x100, got %dx%d", bounds.Dx(), bounds.Dy())
	}
}

func TestGenerateCarrier_NonUniformPixels(t *testing.T) {
	img := GenerateCarrier(64, 64)
	bounds := img.Bounds()

	// Real photos have color variation — check that not all pixels are identical
	firstR, firstG, firstB, _ := img.At(0, 0).RGBA()
	allSame := true
	for y := bounds.Min.Y; y < bounds.Max.Y && allSame; y++ {
		for x := bounds.Min.X; x < bounds.Max.X && allSame; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			if r != firstR || g != firstG || b != firstB {
				allSame = false
			}
		}
	}
	if allSame {
		t.Error("all pixels are identical — carrier should have color variation")
	}
}
