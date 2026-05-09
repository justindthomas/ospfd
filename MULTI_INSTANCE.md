# Multi-Instance ospfd: Single-Process Design

Status: foundation merged (commit `8a6e89c`), orchestration TODO.

## Why we're doing this

VPP's `punt_socket_register` is keyed on `(af, proto, port)` globally:
register-last-wins, no per-FIB-table multiplexing inside VPP.
Two ospfd processes both registering for IP proto 89 silently
fight — the loser sees zero hellos. Same hazard for v3 (af=v6,
proto 89). bgpd@/dnsd@ don't have this problem because they ride
VCL, which IS per-VRF aware via VPP's session-layer
`app_namespace` tagging.

We chose **path 1** over a punt-forwarder shim or a raw-socket
fallback: one ospfd process owns every VRF's state, with an
internal `sw_if_index → instance_idx` demux fanning incoming
packets to the right `OspfInstance`. Single
`punt_socket_register` per af, no cross-instance interference,
no extra IPC hop.

Path NOT chosen and why:
- Punt-forwarder shim: extra daemon, extra hop, still a SPOF
  for proto-89 traffic.
- Raw-socket fallback: makes the dataplane fundamentally
  dependent on the Linux kernel for control-plane RX, which
  the user explicitly rejected.

## What's already in place

Three foundation commits (all on `master`):

`8a6e89c` — multi-instance scaffold:

- `config::OspfDaemonConfig::load_all(path) -> Vec<Self>`:
  returns every v2 instance the YAML declares (default-VRF
  block when `ospf.enabled`, plus one per `ospf.vrfs[]`).
  Per-VRF entries that fail validation get logged-and-skipped
  rather than aborting the whole load.
- `config::Ospf6DaemonConfig::load_all` — same shape for v3.
- `RouterConfig` and the iface/loopback structs gain `Clone`
  so the load can build N configs from one parsed YAML.
- `PuntSocketIo::into_split() -> (PuntSocketRx, PuntSocketTx)`.
  Rx is single-owner (the dispatcher task drains the mpsc); Tx
  is cloneable, with internals behind `Arc`, so per-instance
  event loops each hold a clone. `StdUnixDatagram::send_to` is
  kernel-atomic — concurrent sends across clones are safe with
  no further locking.
- `io::InstanceIo` enum (`Raw(RawSocketIo) | Punt(PuntInstanceIo)`).
  The `Punt` variant carries an instance-specific
  `mpsc::Receiver<RxPacket>` (fed by the dispatcher) plus a
  clone of the shared `PuntSocketTx`. Same `recv` / `send` /
  `interface` surface as `Ospfv2Io` so the existing
  event-loop body works unchanged once `main.rs` swaps types.

## What's left — concrete TODOs

### 1. ospfd `run_daemon` rewrite

Replace the monolithic `run_daemon` with a multi-instance
orchestrator. New shape:

```rust
async fn run_daemon(args: RunArgs) -> anyhow::Result<()> {
    setup_tracing();
    let _lock = acquire_instance_lock(&args.control_socket)?;
    if args.vrf.is_some() {
        tracing::warn!("--vrf deprecated and ignored");
    }

    let v2_configs = OspfDaemonConfig::load_all(&args.config_path)?;
    let v3_configs = Ospf6DaemonConfig::load_all(&args.config_path)?;
    if v2_configs.is_empty() && v3_configs.is_empty() {
        anyhow::bail!("no OSPF instances configured");
    }

    // Connect to VPP, dump interfaces (shared snapshot).
    // VPP-disconnect watcher (single, exits process).

    // For each v2 cfg: build_v2_setup() -> V2InstanceCtx with
    //   instance: Arc<Mutex<OspfInstance>>, io_interfaces.
    // build_v2_ios() -> Vec<InstanceIo>, one per ctx:
    //   - Raw mode: per-instance RawSocketIo (each owns its sockets).
    //   - Punt mode: union all io_interfaces, single
    //     register_punt_v4 + PuntSocketIo::new + into_split,
    //     spawn dispatcher task that forwards by sw_if_index →
    //     instance_idx, hand each instance an mpsc::Receiver +
    //     a tx clone.

    // Single SIGHUP listener -> broadcast::Sender<()>.
    // Single ctrl_c listener -> broadcast::Sender<()>.

    // Spawn one tokio task per v2 instance running run_v2_instance().
    // Same for v3 (when v3 multi-instance lands; for now, if
    // v3_configs.len() > 1 warn and use only [0]).

    // join_all on tasks.
    Ok(())
}
```

### 2. Extract `run_v2_instance`

Lift the existing per-instance event-loop body (currently lines
~660-1574 of main.rs) into a function:

```rust
async fn run_v2_instance(
    ctx: V2InstanceCtx,
    mut io: InstanceIo,
    vpp: Arc<vpp_api::VppClient>,
    config_path: PathBuf,
    mut sighup_rx: broadcast::Receiver<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<()> { … }
```

Per-instance ribd client (each stamps its own `table_id_v4`),
per-instance control socket (`/run/ospfd.sock` for default,
`/run/ospfd@<vrf>.sock` for VRFs — preserves existing query CLI),
per-instance LSDB / neighbor / RIB state. The body of the
existing `tokio::select!` translates 1:1 except `&Ospfv2Io` →
`&InstanceIo` for `send_responses`.

### 3. The dispatcher task

```rust
async fn v4_dispatcher(
    mut rx: PuntSocketRx,
    iface_to_idx: HashMap<u32, usize>,
    senders: Vec<mpsc::Sender<RxPacket>>,
) {
    while let Some(pkt) = rx.recv().await {
        if let Some(&idx) = iface_to_idx.get(&pkt.sw_if_index) {
            if senders[idx].send(pkt).await.is_err() {
                break;
            }
        }
    }
}
```

Same for v3 once v3 multi-instance lands.

### 4. Update `impd::supervisor::ospfd_spec_for_vrf`

Currently spawns one `imp-ospfd@<vrf>` per `ospf.vrfs[]` entry.
Drop the per-VRF children — spawn only the one default
`imp-ospfd`. The single ospfd process now owns every VRF.

```rust
// Before:
let mut ospf_vrf_names: BTreeSet<String> = …;
for v in &cfg.ospf.vrfs { … }
for v in &cfg.ospf6.vrfs { … }
for name in ospf_vrf_names {
    specs.push(ospfd_spec_for_vrf(yaml, Some(&name)));
}

// After: nothing — the default-VRF spec already runs from
// the unconditional block above and now owns all VRFs.
```

The `--vrf` arg goes away from spawn (or stays as a no-op
alias for one release while we let crusty configs cycle through).

### 5. Per-instance control sockets

The existing query CLI is:

```
imp-ospfd query --control-socket /run/ospfd.sock              # default-VRF
imp-ospfd query --control-socket /run/ospfd@customer_vrf.sock  # per-VRF
```

To preserve this without a query-side change, each
`run_v2_instance` task binds its own control socket inside the
single ospfd process. Path is derived from `cfg.vrf_name`:
`None → /run/ospfd.sock`, `Some(v) → /run/ospfd@<v>.sock`.

`control::run_control_server` already takes a path and an
instance handle — call it once per instance with the instance's
own handle.

### 6. v3 — same pattern, follow-up

Mirror the v2 design for v3. Currently `daemon_v3::run`
internally calls `register_punt_v6` and owns its own io;
refactor to take an `InstanceIo`-equivalent (probably a parallel
`io_v3::InstanceIoV3` enum) and have `run_daemon` orchestrate
the v3 dispatcher the same way. Until that lands, gate at
`v3_configs.len() > 1` with a warning so multi-VRF v3 fails
loudly instead of silently.

## Open design questions

Pin these down before writing code:

**Q1. Per-instance control sockets vs single socket with vrf parameter?**
- Option A (recommended): one socket per instance,
  `/run/ospfd.sock` + `/run/ospfd@<vrf>.sock`. Zero CLI change.
- Option B: one socket `/run/ospfd.sock`, query carries
  `--vrf <name>`. Cleaner architecturally but breaks every
  existing tool / runbook / pytest.

→ Go with A. Cost is a few extra `bind` calls; benefit is
nothing externally observable changes.

**Q2. SIGHUP semantics with N instances?**
- New VRF appears in YAML on SIGHUP: spawn a new instance
  task on the fly, or require a daemon restart?
- VRF disappears: tear down the task gracefully, withdraw
  routes from ribd?

→ For v1, SIGHUP only reloads config of EXISTING instances.
Adding/removing VRFs requires a daemon restart. impd's apply
already restarts on supervisor reconcile; the ergonomics
match. Document the limitation in the daemon's
help/journal output.

**Q3. Per-instance ribd connections vs shared multiplexed client?**

→ Per-instance. Each `RibClient` is keyed on a `client_name`
(`ospfd` for default, `ospfd@<vrf>` for per-VRF) and stamps a
`table_id` on every push. ribd's session layer already handles
per-source replace semantics — N connections is the path of
least change. Cost is N socket FDs and N hello/ack exchanges
at startup; both negligible.

**Q4. Lock file path?**

The current `acquire_instance_lock` uses `<control_socket>.lock`.
With multiple control sockets, pick ONE for the process-wide
lock. Recommend: derive from `args.control_socket` (which
defaults to `/run/ospfd.sock`) — that's the global "this
ospfd process" sentinel.

**Q5. v2 + v3 share the same instance, or distinct?**

The existing one-process-per-VRF model has v2 and v3 in the
same process for a given VRF. Keep that: each `V2InstanceCtx`
optionally has a paired `Ospf6Instance`. The v3 dispatcher
fans v6 punt packets to the v3 side. (This means v2 and v3
configs MUST be paired by VRF name, which they already are
in the YAML schema.)

## Test plan

On jt-router (`root@10.11.64.34`), customer_vrf = real test
VRF with a working OSPF NBMA peer to VyOS at 192.168.37.1.

**Pre-deploy baseline:**
- `imp-ospfd query neighbors --control-socket /run/ospfd@customer_vrf.sock`
  shows 10.100.0.1 in `Full` state.
- `ip netns exec dataplane ip route show table 10` shows ~14
  OSPF routes.
- `pgrep -af imp-ospfd` shows TWO processes
  (`imp-ospfd` + `imp-ospfd@customer_vrf`).

**Post-deploy expectations:**
- `pgrep -af imp-ospfd` shows ONE process.
- `journalctl -u impd | grep "registered punt socket"` shows
  exactly ONE registration for proto 89 v4 (path
  `/run/ospfd/punt-v4.sock`).
- Both control sockets exist and respond:
  ```
  imp-ospfd query status --control-socket /run/ospfd.sock
  imp-ospfd query status --control-socket /run/ospfd@customer_vrf.sock
  ```
- Adjacency held continuously through deploy
  (`Full` state survives the supervisor restart).
- VPP table 10 + kernel table 10 still mirror each other.

**Stress shape — the case that catches lock-up regressions:**

Add a SECOND VRF to router.yaml (e.g. `customer2_vrf`) with its
own sub-iface and OSPF area. Restart impd. Verify both
adjacencies form, both punt independently, neither's rx is
clobbering the other. Drop one VRF, restart, verify the other
keeps running.

## Acceptance criteria

- [ ] All 134 existing ospfd unit tests pass.
- [ ] New unit test: `OspfDaemonConfig::load_all` returns the
      right N for a config with default + 2 VRFs.
- [ ] New unit test: dispatcher correctly routes a packet
      with sw_if_index=X to the instance owning X.
- [ ] Live adjacency on jt-router survives deploy
      (post-deploy `query neighbors` shows `Full`).
- [ ] Single `pgrep imp-ospfd` post-deploy.
- [ ] No `[register-last-wins]` in `journalctl -u impd | grep
      punt`.
- [ ] Two-VRF config: both adjacencies form independently and
      survive a restart.

## File-level deltas to expect

```
src/main.rs            -800/+400  (rewrite run_daemon, extract run_v2_instance)
src/io_punt.rs         no change  (split already in place)
src/io.rs              no change  (InstanceIo already in place)
src/config.rs          no change  (load_all already in place)
src/control.rs         maybe +20  (only if Q1 lands as B)
impd/src/supervisor.rs -30 +5     (collapse ospfd_spec_for_vrf)
scripts/external-daemon-versions.txt  +1 -1  (SHA bump)
```

## Pre-flight before next session

- Confirm jt-router state: customer_vrf adjacency Full, kernel
  table 10 mirrored, no journal warnings about punt collisions.
- Confirm no other in-flight changes to `run_daemon` or
  `daemon_v3::run` would conflict.
- Decide Q1 (control-socket layout) — recommend A, codify in
  the prompt.
