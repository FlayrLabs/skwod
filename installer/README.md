# Skwod installer — `skwod init`

One command to stand up a full self-hosted instance. `skwod` is a single self-contained binary that
drives an interactive setup and prints a ready-to-use URL + join code.

```
$ skwod init

Welcome to skwod!

[1/4] Checking Docker... done
[2/4] LiveKit setup
  → API Key: lk_****...****
  → API Secret: ********
[3/4] Starting services... done
[4/4] Running migrations... done

✓ Your instance is ready!

URL: http://localhost:3000
Join code: SKWD-A7X2-M9K3
```

## Design

`skwod` is a **single self-contained Rust binary** — no Node, no runtime dependency. `skwod init` is
a subcommand of that binary; it renders the interactive TUI and orchestrates Docker Compose. All
logic lives in the one audited binary.

Install (any of):
- `curl -fsSL https://get.skwod.sh | sh` — downloads the signed binary for your platform (checksum-verified)
- `brew install skwod`
- download the release binary directly from GitHub Releases

Then: `skwod init`.

## Init steps

| Step | What happens |
|---|---|
| `[1/4] Checking Docker` | Verify Docker Engine + Compose are installed and the daemon is running. If missing, print an OS-specific install hint and exit non-zero. |
| `[2/4] LiveKit setup` | Auto-generate a LiveKit API key + secret (or accept `--livekit-key/--livekit-secret`). Persist to `<data>/config.toml`. Display masked. |
| `[3/4] Starting services` | `docker compose up -d` using [`deploy/docker-compose.yml`](../deploy/docker-compose.yml): one container (server + bundled LiveKit on loopback), SQLite + blob dir on the data volume, running as the invoking user. |
| `[4/4] Running migrations` | `skwod-server migrate` against the DB on the volume. |
| Done | Print the instance `URL` and a freshly generated **admin join code** (`SKWD-XXXX-XXXX`). |

## Flags

| Flag | Meaning |
|---|---|
| `--data <path>` | Storage volume for all state (SQLite + blobs + config). Default `./skwod-data`. |
| `--domain <host>` | Public hostname → URL + TLS via reverse proxy. Default `localhost:3000`. |
| `--database-url <url>` | Use Postgres (`postgres://…`) instead of the default on-volume SQLite. |
| `--s3 <url>` | Use S3-compatible blob storage instead of the volume dir. |
| `--no-livekit` | Skip the voice/video SFU (text-only instance). |
| `--yes` | Non-interactive; accept defaults + auto-generate secrets (for scripted/VPS installs). |

## Security notes

- The install one-liner only downloads the **signed, checksum-verified** binary; it holds no secrets.
- Generated LiveKit secrets and the admin join code live only on the operator's data volume.
- Docker-less path (`skwod-server run --data …`) is under consideration (ADR-008) for environments
  without Docker.

> Status: `init` exists as a subcommand of the server binary (`server/src/init.rs`). The install
> one-liner (`get.skwod.sh`) and the Homebrew formula are **not published**; build from source
> (see the top-level README). The step names above are the design; check `skwod init --help` for
> the flags the binary actually takes.
