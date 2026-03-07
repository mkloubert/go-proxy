# Steganography Performance Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce steganography CPU time per roundtrip from ~20-32ms to ~5-10ms by caching carrier images, using direct pixel-slice access, and adding buffer pooling.

**Architecture:** Three internal optimizations to `internal/stego/` package — carrier caching at init, direct `Pix[]` slice manipulation instead of interface dispatch in Embed/Extract, and `sync.Pool` for PNG encoding buffers. Public API stays identical. No changes outside `internal/stego/`.

**Tech Stack:** Go standard library (`image`, `image/png`, `sync`, `encoding/binary`), no new dependencies.

**Note:** No git operations in this plan. Skip all commit steps.

---

### Task 1: Add Benchmark Tests

**Files:**
- Create: `internal/stego/bench_test.go`

**Step 1: Write benchmark tests**

Create `internal/stego/bench_test.go` with benchmarks for all three operations that will be optimized. These establish the "before" baseline and verify correctness after optimization.

```go
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

func BenchmarkGenerateCarrier_256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateCarrier(256, 256)
	}
}

func BenchmarkGenerateCarrier_1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateCarrier(1024, 1024)
	}
}

func BenchmarkEmbed_256(b *testing.B) {
	carrier := GenerateCarrier(256, 256)
	data := make([]byte, 1024) // 1KB payload
	for i := range data {
		data[i] = byte(i % 251)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Embed(carrier, data)
	}
}

func BenchmarkEmbed_1024(b *testing.B) {
	carrier := GenerateCarrier(1024, 1024)
	data := make([]byte, 64*1024) // 64KB payload
	for i := range data {
		data[i] = byte(i % 251)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Embed(carrier, data)
	}
}

func BenchmarkExtract_256(b *testing.B) {
	carrier := GenerateCarrier(256, 256)
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	pngData, err := Embed(carrier, data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Extract(pngData)
	}
}

func BenchmarkExtract_1024(b *testing.B) {
	carrier := GenerateCarrier(1024, 1024)
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	pngData, err := Embed(carrier, data)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Extract(pngData)
	}
}

func BenchmarkRoundtrip_1024(b *testing.B) {
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		carrier := GenerateCarrier(1024, 1024)
		pngData, err := Embed(carrier, data)
		if err != nil {
			b.Fatal(err)
		}
		_, err = Extract(pngData)
		if err != nil {
			b.Fatal(err)
		}
	}
}
```

**Step 2: Run benchmarks to capture baseline**

Run: `cd /workspace && go test ./internal/stego/ -bench=. -benchmem -count=1 -benchtime=3s`
Expected: All benchmarks run successfully, establishing "before" numbers.

**Step 3: Run existing tests to confirm they pass before changes**

Run: `cd /workspace && go test ./internal/stego/ -v`
Expected: All 11 tests PASS.

---

### Task 2: Implement Carrier Caching (E.1)

**Files:**
- Modify: `internal/stego/carrier.go` (entire file rewrite)

**Step 1: Rewrite carrier.go with caching**

Replace the entire `carrier.go` with this implementation. Key changes:
- Add package-level `carrierCache` map populated in `init()`
- `GenerateCarrier()` clones from cache instead of decoding PNG
- Keep `bestSize()` and `cryptoRandIntn()` unchanged

```go
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
```

**Step 2: Run existing tests to verify correctness**

Run: `cd /workspace && go test ./internal/stego/ -v`
Expected: All 11 tests PASS. The public API is unchanged.

---

### Task 3: Implement Direct Pix-Slice Access + Buffer Pooling (E.2 + E.3)

**Files:**
- Modify: `internal/stego/embed.go` (Embed and Extract functions)

**Step 1: Rewrite embed.go with direct pix access and buffer pooling**

Replace `embed.go` with this implementation. Key changes:
- `Embed()`: Direct `pix[offset]` manipulation instead of `At()`/`SetRGBA()`
- `Embed()`: `sync.Pool` for PNG encoding buffer
- `Extract()`: Type-assert `*image.RGBA` fast path with direct `pix[offset]` access
- `Extract()`: Fallback to RGBA conversion for non-RGBA PNG inputs
- Helper functions (`bytesToBits`, `bitsToBytes`, `getBit`) unchanged

```go
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
	"encoding/binary"
	"errors"
	"image"
	"image/png"
	"sync"
)

const (
	// bitsPerPixel is the number of hidden bits per pixel (2 LSBs x 3 channels).
	bitsPerPixel = 6

	// lengthHeaderSize is the number of bytes used to store the payload length.
	lengthHeaderSize = 4

	// minDimension is the minimum image dimension returned by RequiredImageSize.
	minDimension = 16
)

// pngBufPool reuses buffers for PNG encoding to reduce GC pressure.
var pngBufPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 256*1024))
	},
}

// RequiredImageSize returns the minimum square image dimensions (width, height)
// needed to embed dataLen bytes of payload plus a 4-byte length header.
// The result is always a power of 2 and at least minDimension.
func RequiredImageSize(dataLen int) (int, int) {
	totalBytes := lengthHeaderSize + dataLen
	totalBits := totalBytes * 8

	// Each pixel carries bitsPerPixel bits; we need ceil(totalBits / bitsPerPixel) pixels.
	totalPixels := (totalBits + bitsPerPixel - 1) / bitsPerPixel

	// Find the smallest power-of-2 dimension d such that d*d >= totalPixels.
	dim := minDimension
	for dim*dim < totalPixels {
		dim *= 2
	}

	return dim, dim
}

// Capacity returns the maximum number of payload bytes that can be embedded
// in an image of the given dimensions, excluding the 4-byte length header.
func Capacity(width, height int) int {
	totalPixels := width * height
	totalBits := totalPixels * bitsPerPixel
	totalBytes := totalBits / 8

	cap := totalBytes - lengthHeaderSize
	if cap < 0 {
		return 0
	}
	return cap
}

// Embed hides data inside a clone of carrier using 2-LSB steganography on the
// R, G, B channels (alpha is untouched). A 4-byte big-endian length header is
// prepended to the payload. The result is returned as PNG-encoded bytes.
//
// Returns an error if the payload exceeds the carrier capacity.
func Embed(carrier *image.RGBA, data []byte) ([]byte, error) {
	bounds := carrier.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	maxPayload := Capacity(width, height)
	if len(data) > maxPayload {
		return nil, errors.New("stego: payload too large for carrier image")
	}

	// Build the full message: 4-byte big-endian length + payload.
	header := make([]byte, lengthHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	message := append(header, data...)

	bits := bytesToBits(message)

	// Clone the carrier so we do not modify the original.
	clone := image.NewRGBA(bounds)
	copy(clone.Pix, carrier.Pix)

	// Direct pix-slice access for performance (avoids interface dispatch).
	pix := clone.Pix
	stride := clone.Stride
	bitIdx := 0

	for y := 0; y < height; y++ {
		rowOffset := y * stride
		for x := 0; x < width; x++ {
			offset := rowOffset + x*4

			bit0 := getBit(bits, bitIdx)
			bit1 := getBit(bits, bitIdx+1)
			bit2 := getBit(bits, bitIdx+2)
			bit3 := getBit(bits, bitIdx+3)
			bit4 := getBit(bits, bitIdx+4)
			bit5 := getBit(bits, bitIdx+5)
			bitIdx += bitsPerPixel

			// Replace the 2 LSBs of each channel directly in the pix slice.
			pix[offset] = (pix[offset] & 0xFC) | (bit0 << 1) | bit1
			pix[offset+1] = (pix[offset+1] & 0xFC) | (bit2 << 1) | bit3
			pix[offset+2] = (pix[offset+2] & 0xFC) | (bit4 << 1) | bit5
			// pix[offset+3] (alpha) stays untouched
		}
	}

	// Encode to PNG with fast compression using pooled buffer.
	buf := pngBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer pngBufPool.Put(buf)

	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(buf, clone); err != nil {
		return nil, errors.New("stego: failed to encode PNG: " + err.Error())
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// Extract reads hidden data from PNG-encoded bytes that were produced by Embed.
// It decodes the PNG, reads 2 LSBs from R, G, B per pixel, recovers the 4-byte
// length header and then the payload.
func Extract(pngData []byte) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(pngData))
	if err != nil {
		return nil, errors.New("stego: failed to decode PNG: " + err.Error())
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	// Collect all embedded bits using direct pix-slice access when possible.
	totalBits := width * height * bitsPerPixel
	allBits := make([]byte, 0, totalBits)

	if rgba, ok := img.(*image.RGBA); ok {
		// Fast path: direct pixel array access.
		pix := rgba.Pix
		stride := rgba.Stride

		for y := 0; y < height; y++ {
			rowOffset := y * stride
			for x := 0; x < width; x++ {
				offset := rowOffset + x*4
				r := pix[offset]
				g := pix[offset+1]
				b := pix[offset+2]

				allBits = append(allBits,
					(r>>1)&1, r&1,
					(g>>1)&1, g&1,
					(b>>1)&1, b&1,
				)
			}
		}
	} else {
		// Fallback: use image interface (for non-RGBA PNG inputs).
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				r, g, b, _ := img.At(x, y).RGBA()

				rv := uint8(r >> 8)
				gv := uint8(g >> 8)
				bv := uint8(b >> 8)

				allBits = append(allBits,
					(rv>>1)&1, rv&1,
					(gv>>1)&1, gv&1,
					(bv>>1)&1, bv&1,
				)
			}
		}
	}

	// Read the 4-byte length header (32 bits).
	if len(allBits) < lengthHeaderSize*8 {
		return nil, errors.New("stego: image too small to contain length header")
	}

	headerBytes := bitsToBytes(allBits[:lengthHeaderSize*8])
	payloadLen := binary.BigEndian.Uint32(headerBytes)

	// Validate payload length.
	totalDataBits := (lengthHeaderSize + int(payloadLen)) * 8
	if totalDataBits > len(allBits) {
		return nil, errors.New("stego: declared payload length exceeds image capacity")
	}

	if payloadLen == 0 {
		return []byte{}, nil
	}

	startBit := lengthHeaderSize * 8
	endBit := startBit + int(payloadLen)*8
	payload := bitsToBytes(allBits[startBit:endBit])

	return payload, nil
}

// bytesToBits converts a byte slice into a bit slice (MSB first within each byte).
// Each element of the returned slice is 0 or 1.
func bytesToBits(data []byte) []byte {
	bits := make([]byte, len(data)*8)
	for i, b := range data {
		for j := 7; j >= 0; j-- {
			bits[i*8+(7-j)] = (b >> uint(j)) & 1
		}
	}
	return bits
}

// bitsToBytes converts a bit slice (each element 0 or 1, MSB first) back to bytes.
func bitsToBytes(bits []byte) []byte {
	n := len(bits) / 8
	data := make([]byte, n)
	for i := 0; i < n; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | (bits[i*8+j] & 1)
		}
		data[i] = b
	}
	return data
}

// getBit returns the bit at the given index in the bit slice, or 0 if idx is
// out of range. This prevents index-out-of-bounds when the payload does not
// fill all available pixel capacity.
func getBit(bits []byte, idx int) uint8 {
	if idx < 0 || idx >= len(bits) {
		return 0
	}
	return bits[idx]
}
```

**Step 2: Run all existing tests to verify correctness**

Run: `cd /workspace && go test ./internal/stego/ -v`
Expected: All 11 existing tests PASS. The optimizations must not change behavior.

**Step 3: Run benchmarks to measure improvement**

Run: `cd /workspace && go test ./internal/stego/ -bench=. -benchmem -count=1 -benchtime=3s`
Expected: Significant speedup compared to Task 1 baseline, especially:
- `BenchmarkGenerateCarrier_1024`: 10-20x faster (no PNG decode)
- `BenchmarkEmbed_1024`: 3-5x faster (direct pix access + buffer pool)
- `BenchmarkExtract_1024`: 2-3x faster (direct pix access)

---

### Task 4: Verify Full Integration

**Step 1: Run all project tests**

Run: `cd /workspace && go test ./... 2>&1 | tail -30`
Expected: All tests across the entire project PASS. The stego changes are internal and should not break any tunnel or proxy tests.

**Step 2: Run benchmarks one final time for documentation**

Run: `cd /workspace && go test ./internal/stego/ -bench=. -benchmem -count=3 -benchtime=3s`
Expected: Consistent results across 3 runs confirming the performance improvement.
