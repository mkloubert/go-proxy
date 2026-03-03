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

package security

import "testing"

func TestConnLimiterAcquireRelease(t *testing.T) {
	cl := NewConnLimiter(2)

	if !cl.Acquire() {
		t.Fatal("first Acquire should succeed")
	}
	if !cl.Acquire() {
		t.Fatal("second Acquire should succeed")
	}
	if cl.Acquire() {
		t.Fatal("third Acquire should fail (limit=2)")
	}

	cl.Release()

	if !cl.Acquire() {
		t.Fatal("Acquire after Release should succeed")
	}
}

func TestConnLimiterZero(t *testing.T) {
	cl := NewConnLimiter(0)
	if cl.Acquire() {
		t.Fatal("Acquire on zero-capacity limiter should fail")
	}
}

func TestConnLimiterActive(t *testing.T) {
	cl := NewConnLimiter(3)

	if cl.Active() != 0 {
		t.Fatalf("expected 0 active, got %d", cl.Active())
	}

	cl.Acquire()
	cl.Acquire()

	if cl.Active() != 2 {
		t.Fatalf("expected 2 active, got %d", cl.Active())
	}

	cl.Release()

	if cl.Active() != 1 {
		t.Fatalf("expected 1 active, got %d", cl.Active())
	}
}
