# API v2 compatibility (Terraform/OpenTofu)

Headscale includes a compatibility-oriented implementation of selected Tailscale `/api/v2` endpoints.
The goal is to support practical Terraform/OpenTofu workflows against a self-hosted headscale control plane.

## Scope and intent

- This is a compatibility layer, not a full reimplementation of every Tailscale control API endpoint.
- Behavior is optimized for infrastructure workflows that are common in Terraform/OpenTofu.
- SQLite-first development and testing is supported.

## Authentication

The `/api/v2` layer currently accepts:

- HTTP Basic auth with headscale API key as username.
- HTTP Bearer auth with headscale API key.
- OAuth token flow for provider/client compatibility:
  - `POST /api/v2/oauth/token`
  - `POST /api/v2/oauth/token-exchange`

## Implemented endpoint groups

- Keys:
  - `GET /api/v2/tailnet/{tailnet}/keys`
  - `POST /api/v2/tailnet/{tailnet}/keys`
  - `GET /api/v2/tailnet/{tailnet}/keys/{id}`
  - `DELETE /api/v2/tailnet/{tailnet}/keys/{id}`
- Devices:
  - `GET /api/v2/tailnet/{tailnet}/devices`
  - `GET /api/v2/device/{id}`
  - `DELETE /api/v2/device/{id}`
  - `POST /api/v2/device/{id}/authorized`
  - `POST /api/v2/device/{id}/tags`
  - `POST /api/v2/device/{id}/key`
  - `GET /api/v2/device/{id}/routes`
  - `POST /api/v2/device/{id}/routes`
- ACL:
  - `GET /api/v2/tailnet/{tailnet}/acl`
  - `POST /api/v2/tailnet/{tailnet}/acl`
  - `POST /api/v2/tailnet/{tailnet}/acl/validate`
- Users:
  - `GET /api/v2/tailnet/{tailnet}/users`
  - `GET /api/v2/users/{id}`

## Terraform/OpenTofu support matrix

Status levels:

- `supported`: implemented and validated in local compatibility flow.
- `implemented`: endpoint coverage exists with unit tests, but no dedicated Terraform/OpenTofu smoke harness yet.
- `unsupported`: not implemented in headscale `/api/v2`.

### Resources

| Provider resource | Status | Notes |
| --- | --- | --- |
| `tailscale_tailnet_key` | supported | Validated with local OpenTofu smoke run (`tools/tofu-smoke/run.sh`). |
| `tailscale_acl` | implemented | Includes ETag/If-Match compatibility handling and `details=1` HuJSON wrapper behavior. |
| `tailscale_device_authorization` | implemented | Supports both authorize and deauthorize paths. |
| `tailscale_device_key` | implemented | Key expiry toggle behavior is implemented. |
| `tailscale_device_subnet_routes` | implemented | Supports route read/update endpoints. |
| `tailscale_device_tags` | implemented | Tag updates supported; provider delete calls `SetTags([])` and headscale keeps tags-as-identity constraints. |

### Data sources

| Provider data source | Status | Notes |
| --- | --- | --- |
| `tailscale_acl` | implemented | JSON and HuJSON retrieval behavior implemented. |
| `tailscale_device` | implemented | Node/device lookup paths implemented. |
| `tailscale_devices` | implemented | Device listing and query filtering implemented. |
| `tailscale_user` | implemented | User lookup endpoint implemented. |
| `tailscale_users` | implemented | User listing endpoint implemented. |

### Not currently implemented

Examples of provider objects that are currently `unsupported` in headscale `/api/v2`:

- Resources: `contacts`, `dns_*`, `tailnet_settings`, `webhook`, `logstream_configuration`, `oauth_client`, `aws_external_id`, `federated_identity`, `posture_integration`.
- Data sources: `4via6`.

## Verification and tests

- Unit/integration-style API tests: `hscontrol/tsapi_test.go`.
- Local OpenTofu smoke harness (tailnet key): `tools/tofu-smoke/run.sh`.

When adding new `/api/v2` coverage, update this matrix in the same pull request.
