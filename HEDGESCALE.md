# Hedgescale

An opinionated hard fork of [headscale](https://github.com/juanfont/headscale).
Self-hosted Tailscale control plane that runs anywhere — from a Raspberry Pi
on your desk to edge nodes across the globe.

## Why fork?

Headscale is a great project. But it's downstream of Tailscale LLC's decisions,
constrained by compatibility concerns, and carries architectural baggage
(PostgreSQL support, GORM abstractions) that doesn't serve the self-hosted
community.

Hedgescale makes different bets:

- **SQLite-only.** No PostgreSQL. One file, zero operational overhead.
- **Edge-native.** Optional multi-instance with trivial replication.
- **Pi-friendly.** If it runs well on a Pi 4, it runs well everywhere.
- **Eventually Rust.** Go gets us running. Rust gets us staying.
- **Independent.** No corporate upstream. Community-driven.

## Architecture

### The insight

A Tailscale control plane is a read-heavy coordination service. The NodeStore
(in-memory, copy-on-write snapshots) is the runtime source of truth. SQLite is
just persistence for restart recovery. The hot path — MapRequest polling,
peer lookups, network map generation — is 100% in-memory reads.

Only three operations need linearizable writes:
1. IP address allocation
2. Single-use PreAuthKey consumption
3. Node registration uniqueness

Everything else is eventually consistent *by design*.

### Single instance (default)

The common case. One binary, one SQLite file.

```
hedgescale + nodes.db
```

No configuration beyond the basics. This is the Pi-on-your-desk deployment,
and it should be the best experience in the project.

### Multi-instance (optional)

For availability or geographic distribution. No heavyweight dependencies —
just HTTP.

```
Leader (SQLite + NodeStore)
  │
  ├─ SSE: NodeStore change stream (real-time)
  │
  ├─ Follower (NodeStore, no disk)
  ├─ Follower (NodeStore, no disk)
  └─ Follower (NodeStore, no disk)
        │
        └─ HTTP write forwarding → Leader
```

- **Leader** owns SQLite. Streams NodeStore changes via SSE.
- **Followers** maintain NodeStore in-memory from the change stream. No local
  database needed.
- **Writes** forwarded to leader via plain HTTP.
- **Leader election** starts as config-based. Graduates to automatic
  heartbeat-based promotion later.
- **Follower restart** re-subscribes to SSE, receives full snapshot, then
  incremental deltas.

No NATS. No Raft. No LiteFS. Boring protocols that work everywhere.

## Roadmap

### Phase 0: Fork

Establish hedgescale as its own project.

- [ ] Fork repository, rename project
- [ ] Update module path, binary name, configuration
- [ ] New CLAUDE.md / AGENTS.md reflecting hedgescale's direction
- [ ] CI/CD under hedgescale's own infrastructure

### Phase 1: SQLite-only

Remove PostgreSQL and simplify.

- [ ] Remove `gorm.io/driver/postgres` dependency
- [ ] Remove `PostgresConfig` and `DatabasePostgres` constant
- [ ] Remove Postgres code paths in `db.go` (`openDB`, `runMigrations`)
- [ ] Remove `--postgres` integration test support
- [ ] Simplify `DatabaseConfig` — no more `Type` field, it's always SQLite
- [ ] Audit and tune SQLite pragmas for performance (WAL, mmap, sync modes)
- [ ] Update all documentation and configuration examples

### Phase 2: Slim down

Optimize for modest environments.

- [ ] Audit dependency tree — remove anything not pulling its weight
- [ ] Profile memory usage, identify and fix allocations on hot path
- [ ] Reduce binary size (strip unnecessary features, review build tags)
- [ ] Benchmark on Pi 4 — establish baseline numbers
- [ ] Evaluate GORM: keep, replace with lighter ORM, or go raw `database/sql`
- [ ] Review and simplify configuration surface area

### Phase 3: Extract read/write seam

Prepare the architecture for optional distribution. No behavioral change.

- [ ] Define `WriteService` interface for all linearizable operations
  - `RegisterNode`, `AllocateIP`, `ConsumePreAuthKey`
  - Node mutations, user management, policy updates
- [ ] `LocalWriteService`: current behavior, direct SQLite writes
- [ ] Ensure all reads go through NodeStore (audit any remaining direct DB reads
  on hot path)
- [ ] Clean separation: reads never touch WriteService, writes never read from
  NodeStore

### Phase 4: Optional replication

Multi-instance support as an additive feature.

- [ ] SSE endpoint on leader streaming NodeStore change events
- [ ] Follower mode: subscribe to SSE, maintain local NodeStore
- [ ] HTTP write forwarding from followers to leader
- [ ] Full NodeStore snapshot on follower connect/reconnect
- [ ] Leader configuration (initially config-based)
- [ ] Health checks and follower status reporting
- [ ] Graceful degradation: followers serve stale data if leader unreachable
- [ ] Integration tests for multi-instance scenarios

### Phase 5: Automatic leader election

Remove manual leader configuration.

- [ ] Heartbeat protocol between instances
- [ ] Leader lease with timeout-based expiry
- [ ] Automatic follower promotion on leader failure
- [ ] Fencing: old leader must stop accepting writes after lease loss
- [ ] SQLite ownership transfer on leader change

### Phase 6: Rust

With architecture proven and boundaries clean, rewrite.

- [ ] Evaluate Rust SQLite options (rusqlite, sqlx, diesel)
- [ ] Evaluate Rust Tailscale protocol compatibility
- [ ] Incremental or big-bang rewrite strategy (TBD based on state of things)
- [ ] Maintain wire compatibility with existing Tailscale clients

## Principles

**Boring is good.** HTTP over custom protocols. SQLite over distributed
databases. Config files over service discovery. Complexity is earned, not
assumed.

**Single-instance is first class.** Multi-instance is a feature, not a
requirement. Every architectural decision must make single-instance better
or at worst not worse.

**Pi is the benchmark.** If it doesn't run well on a Raspberry Pi 4 with
2GB RAM, it's too heavy.

**No corporate upstream.** Hedgescale tracks Tailscale's *protocol*, not their
product decisions. We implement what serves self-hosters.

## Prior art and acknowledgments

- [headscale](https://github.com/juanfont/headscale) — the original. This
  project exists because of their work.
- [LiteFS](https://github.com/superfly/litefs) — inspiration for the
  edge-SQLite model, even if we go simpler.
- [Tailscale](https://tailscale.com/) — great client software, complicated
  relationship with open source.
