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
	New: func() any {
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
