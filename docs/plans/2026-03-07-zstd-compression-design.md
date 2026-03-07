# Design: zstd Compression in EncryptedConn (Frame-Level)

**Date:** 2026-03-07
**Milestone:** Tunnel optimization
**Concept:** D (Data compression before encryption)

## Overview

Add transparent zstd compression at the frame level inside `EncryptedConn`. Compression happens before encryption, decompression after decryption. Per-frame decision: only compress when it actually reduces size.

## Frame Header Change

```
Current:   [Bit 0-31: frame payload length]
New:       [Bit 31:   1=compressed, 0=uncompressed]
           [Bit 0-30: frame payload length (max ~2GB)]
```

The flag lives inside the encrypted tunnel protocol and is invisible from the outside (HTTP, PNG, DPI).

## Data Flow

```
Write path: Plaintext -> zstd compress (if beneficial) -> AES-256-GCM encrypt -> Frame header -> Wire
Read path:  Wire -> Frame header -> AES-256-GCM decrypt -> zstd decompress (if flag set) -> Plaintext
```

## Changes to EncryptedConn

### New Fields

- `zstdEnc *zstd.Encoder` — reusable, `SpeedDefault` level
- `zstdDec *zstd.Decoder` — reusable, with `DecoderMaxMemory(MaxFrameSize * 2)` for decompression bomb protection

### writeFrame()

1. Compress plaintext with `zstdEnc.EncodeAll(plaintext, nil)`
2. If `len(compressed) < len(plaintext)`: use compressed data + set bit 31
3. Otherwise: use original plaintext, bit 31 stays 0
4. Rest unchanged (nonce, GCM Seal, frame assembly)

### readFrame()

1. Read 4-byte header
2. Extract bit 31 as `isCompressed`
3. Mask out bit 31: `frameLen = rawLen &^ compressedBit`
4. Validate length (as before, but with masked value)
5. Read + decrypt as before
6. If `isCompressed`: decompress with `zstdDec.DecodeAll(plaintext, nil)`

### Close()

- Call `zstdEnc.Close()` and `zstdDec.Close()` to release resources

## Security

- **Decompression bomb protection:** `zstd.WithDecoderMaxMemory(MaxFrameSize * 2)`
- **No overhead for binary data:** If compression does not help, data is sent uncompressed
- **Compress before encrypt:** Correct order (encrypted data is not compressible)
- Flag is inside the encrypted tunnel, invisible to external observers

## Files Changed

1. `internal/crypto/tunnel.go` — main changes (EncryptedConn struct, writeFrame, readFrame, Close)
2. `internal/crypto/tunnel_test.go` — new compression tests
3. `go.mod` / `go.sum` — new dependency (`github.com/klauspost/compress`)

## Compatibility

No backward compatibility required. Both client and server must use the same version.

## Expected Impact

| Data type | Typical compression ratio | Effect |
|-----------|--------------------------|--------|
| HTML | 70-85% | Much smaller PNGs |
| JSON/API | 75-90% | Dramatically smaller PNGs |
| CSS/JS | 60-75% | Noticeably smaller PNGs |
| Binary (JPEG, ZIP) | 0-5% | No overhead (flag = uncompressed) |

Estimated improvement: 40-80% less data volume for text traffic.
