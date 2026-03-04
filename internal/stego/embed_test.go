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
	"testing"
)

func TestRequiredImageSize_SmallPayload(t *testing.T) {
	w, h := RequiredImageSize(100)

	if w < minDimension || h < minDimension {
		t.Errorf("expected dimensions >= %d, got %dx%d", minDimension, w, h)
	}

	if w != 16 || h != 16 {
		t.Errorf("expected 16x16 for 100 bytes, got %dx%d", w, h)
	}

	// Verify the dimensions actually have enough capacity.
	cap := Capacity(w, h)
	if cap < 100 {
		t.Errorf("capacity %d is less than payload size 100", cap)
	}
}

func TestRequiredImageSize_LargePayload(t *testing.T) {
	// 192KB = 196608 bytes. With 4-byte header = 196612 bytes = 1572896 bits.
	// Pixels needed = ceil(1572896 / 6) = 262150. 512*512 = 262144 < 262150,
	// so we need 1024x1024.
	payloadSize := 192 * 1024 // 192 KB
	w, h := RequiredImageSize(payloadSize)

	if w != 1024 || h != 1024 {
		t.Errorf("expected 1024x1024 for 192KB payload, got %dx%d", w, h)
	}

	// Verify the dimensions actually have enough capacity.
	cap := Capacity(w, h)
	if cap < payloadSize {
		t.Errorf("capacity %d is less than payload size %d", cap, payloadSize)
	}

	// Also verify that the next smaller power-of-2 is insufficient.
	smallerCap := Capacity(w/2, h/2)
	if smallerCap >= payloadSize {
		t.Errorf("smaller image %dx%d has capacity %d >= payload %d, dimension should be smaller",
			w/2, h/2, smallerCap, payloadSize)
	}
}

func TestEmbedExtract_Roundtrip(t *testing.T) {
	message := []byte("hello steganography world! this is a secret message.")
	carrier := GenerateCarrier(256, 256)

	pngData, err := Embed(carrier, message)
	if err != nil {
		t.Fatalf("Embed failed: %v", err)
	}

	// Verify PNG signature (first 8 bytes).
	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(pngData) < 8 {
		t.Fatal("PNG data is too short")
	}
	if !bytes.Equal(pngData[:8], pngSignature) {
		t.Errorf("PNG signature mismatch: got %x, expected %x", pngData[:8], pngSignature)
	}

	extracted, err := Extract(pngData)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if !bytes.Equal(extracted, message) {
		t.Errorf("roundtrip mismatch:\n  expected: %q\n  got:      %q", message, extracted)
	}
}

func TestEmbedExtract_EmptyPayload(t *testing.T) {
	carrier := GenerateCarrier(16, 16)

	pngData, err := Embed(carrier, []byte{})
	if err != nil {
		t.Fatalf("Embed failed for empty payload: %v", err)
	}

	extracted, err := Extract(pngData)
	if err != nil {
		t.Fatalf("Extract failed for empty payload: %v", err)
	}

	if len(extracted) != 0 {
		t.Errorf("expected empty payload, got %d bytes: %q", len(extracted), extracted)
	}
}

func TestEmbedExtract_MaxCapacity(t *testing.T) {
	width, height := 256, 256
	carrier := GenerateCarrier(width, height)

	maxPayload := Capacity(width, height)
	if maxPayload <= 0 {
		t.Fatalf("capacity for %dx%d should be > 0, got %d", width, height, maxPayload)
	}

	// Fill max-capacity payload with a repeating pattern.
	data := make([]byte, maxPayload)
	for i := range data {
		data[i] = byte(i % 251) // prime modulus for varied pattern
	}

	pngData, err := Embed(carrier, data)
	if err != nil {
		t.Fatalf("Embed failed for max capacity: %v", err)
	}

	extracted, err := Extract(pngData)
	if err != nil {
		t.Fatalf("Extract failed for max capacity: %v", err)
	}

	if !bytes.Equal(extracted, data) {
		t.Errorf("roundtrip mismatch at max capacity (%d bytes)", maxPayload)
		// Find first mismatch for debugging.
		for i := range data {
			if i >= len(extracted) {
				t.Errorf("  extracted is shorter: %d vs %d", len(extracted), len(data))
				break
			}
			if data[i] != extracted[i] {
				t.Errorf("  first mismatch at byte %d: expected 0x%02x, got 0x%02x", i, data[i], extracted[i])
				break
			}
		}
	}
}

func TestEmbed_PayloadTooLarge(t *testing.T) {
	carrier := GenerateCarrier(64, 64)

	bigPayload := make([]byte, 4000)
	for i := range bigPayload {
		bigPayload[i] = byte(i)
	}

	_, err := Embed(carrier, bigPayload)
	if err == nil {
		t.Error("expected error for oversized payload, got nil")
	}
}
