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

// ConnLimiter limits the number of concurrent connections using a
// channel-based semaphore. Acquire is non-blocking: it returns false
// immediately when the limit is reached.
type ConnLimiter struct {
	sem chan struct{}
}

// NewConnLimiter creates a ConnLimiter with the given maximum capacity.
func NewConnLimiter(maxConns int) *ConnLimiter {
	return &ConnLimiter{
		sem: make(chan struct{}, maxConns),
	}
}

// Acquire tries to acquire a connection slot. Returns false if full.
func (cl *ConnLimiter) Acquire() bool {
	select {
	case cl.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees a connection slot.
func (cl *ConnLimiter) Release() {
	<-cl.sem
}

// Active returns the number of currently held slots.
func (cl *ConnLimiter) Active() int {
	return len(cl.sem)
}
