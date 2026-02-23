# /api/v2 Liberation Plan

## Mission

Deliver a practical `/api/v2` compatibility layer in headscale so Terraform/OpenTofu users can manage their tailnet-like resources without depending on tailscale.com.

## Threat Model (Explicit)

Assume the upstream hosted control plane may be unavailable, incompatible, or operated in bad faith toward self-hosters. We therefore optimize for operator sovereignty:

- own the control plane,
- own the API surface required for automation,
- own infrastructure lifecycle via Terraform/OpenTofu.

## North-Star Outcome

Running Terraform/OpenTofu against headscale should create/update/delete the mapped resources that headscale already supports, with stable state convergence and no manual API patching.

In short: **terraform today, k8s operator tomorrow**.

## Scope Boundary

Only implement resource behavior where headscale has existing backing primitives today.

- no speculative APIs,
- no fake persistence beyond bootstrap necessities,
- no net-new control-plane concepts unless required for compatibility.

## Success Criteria (Overall)

For each in-scope resource:

1. `tofu apply` (or `terraform apply`) creates expected objects in headscale.
2. A second apply is idempotent (`No changes`).
3. Supported updates reconcile correctly (in-place or replace-when-immutable).
4. `tofu destroy` removes/deactivates the object as expected.
5. Read-back from provider matches headscale state.

"Update" means one of:

- true in-place mutation (preferred), or
- replace semantics when resource is immutable in headscale.

## Resource Mapping (Current Target)

These are the obvious Terraform/OpenTofu bits to target first, because headscale already has underlying support:

1. **Auth Keys** (backed by PreAuthKeys)
   - create/list/get/delete (or expire/delete semantics)
2. **Devices / Nodes**
   - read/list/delete
   - mutate where supported: tags, authorization/expiry, routes
3. **ACL Policy**
   - read/validate/set (DB mode where applicable)
4. **Users (read-focused initially)**
   - list/get for provider data hydration

## Immediate Slice (Next Hour)

### Goal

Ship one simple, reliable Terraform/OpenTofu resource path end-to-end.

### Chosen Slice

**Auth key resource flow** (`/api/v2/tailnet/-/keys` family).

### Required API surface for this slice

- `POST /api/v2/oauth/token` (bootstrap credentials)
- `POST /api/v2/oauth/token-exchange` (operator/client compatibility)
- `GET /api/v2/tailnet/{tailnet}/keys`
- `POST /api/v2/tailnet/{tailnet}/keys`
- `GET /api/v2/tailnet/{tailnet}/keys/{id}`
- `DELETE /api/v2/tailnet/{tailnet}/keys/{id}`

### Pass/Fail for this slice

Pass when all are true:

1. apply creates key resource successfully,
2. re-apply is idempotent,
3. destroy removes/deactivates the key as expected,
4. provider reports consistent read state throughout.

## Harness Plan (Simple, No Fancy Orchestration)

Keep it straightforward and repeatable:

1. start headscale (SQLite, local config),
2. generate bootstrap API key,
3. run minimal Terraform/OpenTofu fixture against headscale base URL,
4. assert create/update/destroy behavior via provider outputs and API read-back,
5. keep fixture and command transcript for regression use.

No beads/parallel agent setup required for now.

## Phase Plan

### Phase 0 - Baseline

- Lock bootstrap auth behavior for `/api/v2`.
- Ensure JSON/error shapes are provider-compatible for the first slice.

### Phase 1 - Terraform MVP (Keys First)

- Complete and validate auth key lifecycle.
- Codify fixture as canonical smoke test.

### Phase 2 - Expand Terraform Coverage

- Add device lifecycle/mutations where headscale already supports them.
- Add ACL lifecycle support.
- Add user read endpoints required by provider behavior.

### Phase 3 - Stability and Compatibility

- Tighten edge-case behavior (status codes, filtering, field names, id formats).
- Add regression tests for every implemented resource lifecycle.

### Phase 4 - k8s Operator Bring-Up (Tomorrow)

- Reuse OAuth/token paths and key/device APIs.
- Validate operator startup and first reconcile loops.

## Non-Goals (for this sprint)

- Full tailscale.com feature parity.
- New headscale primitives unrelated to current Terraform/provider needs.
- Premature optimization over compatibility correctness.

## Practical Definition of MVP Done

MVP is done when a small but real Terraform/OpenTofu config against headscale can manage at least one resource end-to-end now (auth key), and we have a clear path and fixtures to incrementally add the next obvious resources.
