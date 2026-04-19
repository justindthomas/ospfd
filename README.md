# ospfd

OSPFv2 (RFC 2328) + OSPFv3 (RFC 5340) daemon that programs routes directly into [VPP's](https://fd.io) FIB by pushing them to [ribd](https://github.com/justindthomas/ribd).

Designed to run inside a VPP-hosted network namespace alongside `linux_cp` TAP interfaces for packet I/O. Programs VPP's FIB via the binary API, not the Linux routing table.

## Build

```sh
cargo build --release
```

Requires a protobuf-free toolchain; depends on [`vpp-api`](https://github.com/justindthomas/vpp-api), [`ribd-proto`](https://github.com/justindthomas/ribd), and [`ribd-client`](https://github.com/justindthomas/ribd).

## Run

```sh
ospfd --config /etc/ospfd/config.yaml
```

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--config PATH` | `/etc/ospfd/config.yaml` | Config file (see below) |
| `--vpp-api SOCKET` | `/run/vpp/api.sock` | VPP binary API socket |
| `--control-socket PATH` | `/run/ospfd.sock` | Unix socket for `query` subcommands |
| `--io raw\|punt` | `raw` | Packet I/O backend (raw sockets on TAPs, or VPP punt sockets) |

## Query a running daemon

```sh
ospfd query status
ospfd query neighbors
ospfd query interfaces
ospfd query database --area 0.0.0.0 --type router
ospfd query routes
```

v3 equivalents: `status6`, `neighbors6`, `interfaces6`, `database6`, `routes6`.

## Configuration

YAML with `ospf:` and/or `ospf6:` top-level keys. See `examples/` for a minimal config.

`SIGHUP` re-reads the config and hot-applies changes to per-interface timers (hello/dead/retransmit/transmit-delay), priority, cost, and passive flag; `redistribute` and `summary_addresses` are replaced wholesale. Changes to `router_id`, network type, area membership, or interface add/remove require a daemon restart and are logged as warnings on reload.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

If the AGPL's obligations are incompatible with your use, commercial licenses are available. See [CONTRIBUTING.md](CONTRIBUTING.md).
