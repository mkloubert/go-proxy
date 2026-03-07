# Design: Steganography Performance Optimization (Konzept E)

## Date

2026-03-07

## Goal

Optimize the steganography subsystem (`internal/stego/`) to reduce CPU time per roundtrip from ~20-32ms to ~5-10ms. All changes are internal — the public API remains unchanged.

## Changes

### E.1: Carrier Caching (`carrier.go`)

**Problem:** `GenerateCarrier()` decodes an embedded PNG and converts to RGBA on every call (~2-5ms per call).

**Solution:** Load and decode all 63 carrier images (7 sizes x 9 variants) once at package init. Cache as `map[int][]*image.RGBA`. `GenerateCarrier()` reduces to a `copy(clone.Pix, src.Pix)` operation (~0.1-0.5ms).

**Memory cost:** ~35MB one-time allocation (acceptable for a proxy daemon).

### E.2: Direct Pix-Slice Access (`embed.go`)

**Problem:** `Embed()` uses `SetRGBA(x, y, color)` and `Extract()` uses `At(x,y).RGBA()` — both go through Go's image interface dispatch, which is slow for hot loops over millions of pixels.

**Solution:**
- `Embed()`: Work directly on `clone.Pix[offset]` instead of `SetRGBA()`
- `Extract()`: Type-assert `img.(*image.RGBA)` for fast path, then read directly from `pix[offset]`
- Keep RGBA conversion fallback in `Extract()` for non-RGBA PNG inputs

**Expected speedup:** Embed 3-5x faster, Extract 2-3x faster.

### E.3: Buffer Pooling (`embed.go`)

**Problem:** Each `Embed()` call allocates a new `bytes.Buffer` for PNG encoding. At 20+ roundtrips/second, this creates GC pressure and latency spikes.

**Solution:** Use `sync.Pool` with pre-allocated 256KB buffers. `Embed()` gets a buffer from the pool, encodes, copies the result, and returns the buffer to the pool.

**Expected improvement:** ~10-20% less CPU overhead on PNG encoding.

## Files Changed

- `internal/stego/carrier.go` — carrier caching in init()
- `internal/stego/embed.go` — direct pix access + buffer pooling
- `internal/stego/embed_test.go` — benchmark tests

## Testing

- All 11 existing tests must continue to pass (no API changes)
- New benchmark tests: `BenchmarkEmbed`, `BenchmarkExtract`, `BenchmarkGenerateCarrier`
- New test for carrier cache initialization

## Expected Results

| Operation | Before | After |
|-----------|--------|-------|
| Carrier generation | ~2-5ms (PNG decode) | ~0.1-0.5ms (pix copy) |
| Embed (1024x1024) | ~10-15ms | ~3-5ms |
| Extract (1024x1024) | ~8-12ms | ~2-4ms |
| **Total per roundtrip** | **~20-32ms** | **~5-10ms** |
