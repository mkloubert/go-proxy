# go-proxy

A CLI tool that provides a local HTTP/HTTPS/SOCKS5 proxy with an encrypted tunnel to a remote server. It prevents man-in-the-middle attacks in untrusted networks by disguising tunnel traffic as a normal image gallery API.

## How It Works

`go-proxy` has two modes:

- **Remote mode**: Runs on a trusted server with direct internet access. It serves an HTTP gallery API that secretly carries encrypted tunnel data inside PNG images.
- **Local mode**: Runs on your machine in the untrusted network. It accepts proxy connections (HTTP, HTTPS, SOCKS5) and sends all traffic through the steganographic tunnel to the remote server.

All data between local and remote is encrypted with AES-256-GCM and hidden inside valid PNG images using LSB steganography. The tunnel looks like normal HTTP traffic to an image gallery API, making it compatible with restrictive corporate proxies that perform TLS interception.

```
Your Machine (untrusted network)        Trusted Server
+---------------------------+           +---------------------------+
| Browser / App             |           |                           |
|       |                   |           |                           |
| [go-proxy local]          |  HTTP/1.1 | [go-proxy remote]         |
| HTTP/HTTPS/SOCKS5 proxy   |<--------->| Gallery API server        |
| 127.0.0.1:12345           |  PNG with |       |                   |
+---------------------------+  hidden   |   Internet                |
                               data     +---------------------------+
```

## How the Tunnel Works

The tunnel disguises itself as a REST API for an image gallery:

1. Every request is a `POST /api/v1/galleries/{uuid}/pictures` with a PNG image body.
2. Upstream data (from your apps) is encrypted with AES-256-GCM and hidden inside the PNG using 2-bit LSB steganography on the R, G, B channels.
3. The server extracts the hidden data, processes it, and responds with another PNG containing the downstream data.
4. A random UUID is used for each request, making every URL unique.
5. Only standard HTTP headers are used: `Content-Type: image/png` and `Authorization: Bearer <token>`.

This makes the traffic look like a normal image upload API to any proxy, firewall, or TLS inspection device.

## Build

```bash
go build -o go-proxy .
```

## Setup

### 1. Create a Shared Secret

Generate a random secret and encode it as base64:

```bash
# Generate a 32-byte random key and encode as base64
openssl rand -base64 32
```

Set this value as an environment variable on both machines:

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
```

### 2. Start the Remote Server

On the trusted server (with direct internet access):

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy remote --port=80
```

### 3. Start the Local Proxy

On your local machine (in the untrusted network):

```bash
export GOPROXY_TUNNEL_SECRET="your-base64-encoded-secret-here"
./go-proxy local --port=12345 --connect-to="http://your-server.com:80"
```

### 4. Configure Your Applications

Point your browser or application to use the local proxy:

- **HTTP/HTTPS proxy**: `http://127.0.0.1:12345`
- **SOCKS5 proxy**: `socks5://127.0.0.1:12345`

#### Example with curl

```bash
# HTTP proxy
curl -x http://127.0.0.1:12345 https://example.com

# SOCKS5 proxy
curl --socks5 127.0.0.1:12345 https://example.com
```

#### Example with environment variables

```bash
export HTTP_PROXY=http://127.0.0.1:12345
export HTTPS_PROXY=http://127.0.0.1:12345
```

## CLI Reference

### `go-proxy local`

Start the local proxy.

| Flag           | Short | Default    | Description                                    |
| -------------- | ----- | ---------- | ---------------------------------------------- |
| `--port`       | `-p`  | 8080       | Port for the local proxy                       |
| `--connect-to` | `-c`  | (required) | Remote server URL (e.g., `http://host.com:80`) |
| `--verbose`    | `-v`  | false      | Enable debug logging                           |

### `go-proxy remote`

Start the remote tunnel server.

| Flag        | Short | Default | Description                |
| ----------- | ----- | ------- | -------------------------- |
| `--port`    | `-p`  | 9876    | Port for the remote server |
| `--verbose` | `-v`  | false   | Enable debug logging       |

### Environment Variables

| Variable                    | Description                                                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `GOPROXY_TUNNEL_SECRET`     | Base64-encoded shared secret for AES-256 tunnel encryption (required)                                                      |
| `GOPROXY_BLOCKED_COUNTRIES` | Comma-separated ISO country codes to block (e.g. `CN,RU,IR`). Only used when `GeoLite2.mmdb` is present. Case-insensitive. |

## IP Blocking (Remote Server)

The remote server can block incoming connections based on IP reputation and geolocation. Both features are optional and activate automatically when their data files are present in the working directory.

### ipsum.txt (Threat Intelligence)

Place an `ipsum.txt` file (from [stamparm/ipsum](https://github.com/stamparm/ipsum)) in the working directory of the remote server. IPs with a threat level of 3 or higher are blocked automatically.

```bash
# Download the latest ipsum.txt
curl -o ipsum.txt https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
```

### GeoLite2 Country Blocking

Place a `GeoLite2.mmdb` file (from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)) in the working directory and set the `GOPROXY_BLOCKED_COUNTRIES` environment variable.

```bash
export GOPROXY_BLOCKED_COUNTRIES="CN,RU,IR"
./go-proxy remote --port=80
```

Country codes are [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2), case-insensitive, and whitespace is trimmed.

## Security

- All tunnel traffic is hidden inside valid PNG images using LSB steganography.
- The tunnel looks like a normal image gallery REST API to network observers.
- All data is encrypted with AES-256-GCM before being embedded in images.
- Keys are derived using HKDF (SHA-256) with a random salt per session.
- A challenge/response handshake verifies both sides share the same secret.
- The encryption key is never logged.
- Only standard HTTP headers are used (`Content-Type`, `Authorization`).
- IP blocking via threat intelligence feeds and GeoIP country filtering (remote server).
- SSRF protection prevents the remote server from connecting to private/internal IPs.

## License

[MIT License](./LICENSE)
