# vpn-proxy

<p align="left">
  <a href="https://github.com/marcohefti/vpn-proxy/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/marcohefti/vpn-proxy/ci.yml?branch=main&amp;label=ci&amp;style=flat-square"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/marcohefti/vpn-proxy?style=flat-square"></a>
  <a href="https://hub.docker.com/r/qmcgaw/gluetun"><img alt="Gluetun" src="https://img.shields.io/badge/gluetun-v3-blue?style=flat-square"></a>
</p>

CLI-first VPN proxy stack for operators who want:

- one config file
- deterministic tunnel generation
- quick start + quick health checks

## Prerequisites

- Docker (`docker compose`)
- Optional: Python 3.11+ (faster local execution of `scripts/proxyctl.py`)

`./proxyctl` works even without local Python (Dockerized fallback).

## Quick Install

```bash
git clone <your-repo-url> vpn-proxy
cd vpn-proxy
chmod +x proxyctl
```

## Quick Start

```bash
./proxyctl init --provider nordvpn
./proxyctl up
./proxyctl status
./proxyctl check
```

Stop:

```bash
./proxyctl down
```

## Command Surface

```bash
./proxyctl init --provider nordvpn
./proxyctl edit
./proxyctl generate
./proxyctl up
./proxyctl down
./proxyctl status
./proxyctl endpoints
./proxyctl doctor
./proxyctl check
```

Common flags:

- `--config /path/to/proxy.toml`
- `init --template`
- `up --wait`
- `up --wait --wait-timeout 180`
- `down --remove-volumes`
- `check --url https://api.ipify.org --timeout 20`

## Config Model

Main file: `proxy.toml`

- `[project]` project metadata and output path
- `[defaults]` runtime defaults (includes pinned image `qmcgaw/gluetun:v3`)
- `[provider]` provider credentials/settings
- `[tunnel_pool]` tunnel count + regions + naming/port strategy

Example:

```toml
[tunnel_pool]
count = 2
regions = ["Finland", "Netherlands"]
selector = "country"
name_prefix = "proxy"
port_start = 8111
```

Want different countries? Edit `regions` directly.

## NordVPN Credentials

Use NordVPN **manual service credentials** (not account email/password).

- Path: `Nord Account -> NordVPN -> Manual setup -> Set up NordVPN manually -> Service Credentials`
- URL: https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/service-credentials/

## Operator Checks

Environment/config validation:

```bash
./proxyctl doctor
```

Per-proxy connectivity check:

```bash
./proxyctl check
```

## Troubleshooting

- `AUTH_FAILED` -> wrong VPN credentials; use manual service credentials.
- `CONNECT tunnel failed, response 503` -> container is up but tunnel handshake is still in progress.
- One proxy unhealthy while others are healthy -> region-specific issue; change `[tunnel_pool].regions`.
- Need strict startup gating -> run `./proxyctl up --wait`.

## Generated Artifacts

- `.proxy/compose.yml`
- `.proxy/secrets/*`

`proxy.toml` and `.proxy/` are gitignored by default.

## Security Defaults

- Proxy binds to `127.0.0.1` by default.
- Control API disabled by default.
- Secret values are written to local files with restrictive permissions when possible.

If you expose bind address beyond localhost, apply host firewall rules.

## License

MIT (`LICENSE`).

## Legal Use

You are responsible for compliant and lawful usage:

- follow your VPN provider’s Terms of Service
- follow local laws/regulations in your jurisdiction
- do not use this project for abuse, fraud, or unauthorized access
