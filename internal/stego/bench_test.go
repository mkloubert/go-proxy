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

// BenchmarkGenerateCarrier_256 benchmarks carrier generation at 256x256.
func BenchmarkGenerateCarrier_256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateCarrier(256, 256)
	}
}

// BenchmarkGenerateCarrier_1024 benchmarks carrier generation at 1024x1024.
func BenchmarkGenerateCarrier_1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateCarrier(1024, 1024)
	}
}

// BenchmarkEmbed_256 benchmarks embedding 1KB into a 256x256 carrier.
func BenchmarkEmbed_256(b *testing.B) {
	carrier := GenerateCarrier(256, 256)

	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i % 251)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Embed(carrier, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEmbed_1024 benchmarks embedding 64KB into a 1024x1024 carrier.
func BenchmarkEmbed_1024(b *testing.B) {
	carrier := GenerateCarrier(1024, 1024)

	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 251)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Embed(carrier, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExtract_256 benchmarks extraction from a 256x256 PNG.
func BenchmarkExtract_256(b *testing.B) {
	carrier := GenerateCarrier(256, 256)

	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i % 251)
	}

	pngData, err := Embed(carrier, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Extract(pngData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExtract_1024 benchmarks extraction from a 1024x1024 PNG.
func BenchmarkExtract_1024(b *testing.B) {
	carrier := GenerateCarrier(1024, 1024)

	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 251)
	}

	pngData, err := Embed(carrier, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Extract(pngData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRoundtrip_1024 benchmarks a full roundtrip (GenerateCarrier + Embed + Extract)
// with a 64KB payload at 1024x1024.
func BenchmarkRoundtrip_1024(b *testing.B) {
	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 251)
	}

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
