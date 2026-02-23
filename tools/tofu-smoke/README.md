# Local OpenTofu Smoke (SQLite + /api/v2)

This is a copy/paste-friendly smoke flow for running headscale from source with
SQLite and exercising a minimal `tailscale_tailnet_key` lifecycle via
OpenTofu using the stable provider release.

If you just want the automated flow, run:

```bash
./tools/tofu-smoke/run.sh
```

Optional:

```bash
./tools/tofu-smoke/run.sh --keep
./tools/tofu-smoke/run.sh --provider-version 0.28.0
```

## Prerequisites

- `go`
- `tofu`

## 1) Start local headscale in a temp sandbox

```bash
# from repo root
pick_port(){
  python - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

export HS_PORT="$(pick_port)"
export HS_GRPC_PORT="$(pick_port)"
export HS_TMPDIR="$(mktemp -d)"
export HS_CONFIG="$HS_TMPDIR/config.yaml"
export HS_SOCKET="$HS_TMPDIR/headscale.sock"

cat > "$HS_CONFIG" <<EOF
server_url: http://127.0.0.1:${HS_PORT}
listen_addr: 127.0.0.1:${HS_PORT}
metrics_listen_addr: ""
grpc_listen_addr: 127.0.0.1:${HS_GRPC_PORT}
grpc_allow_insecure: true

noise:
  private_key_path: ${HS_TMPDIR}/noise.key

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48

derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: false

database:
  type: sqlite
  sqlite:
    path: ${HS_TMPDIR}/headscale.sqlite

policy:
  mode: file
  path: ""

dns:
  magic_dns: false
  base_domain: example.test
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []

unix_socket: ${HS_SOCKET}
unix_socket_permission: "0770"

log:
  level: info
  format: text
EOF

go run ./cmd/headscale -c "$HS_CONFIG" serve >"$HS_TMPDIR/server.log" 2>&1 &
export HS_PID=$!

# wait for unix socket
for i in $(seq 1 40); do
  [ -S "$HS_SOCKET" ] && break
  sleep 1
done

if [ ! -S "$HS_SOCKET" ]; then
  echo "headscale did not start"
  cat "$HS_TMPDIR/server.log"
  exit 1
fi

export TS_API_KEY="$(go run ./cmd/headscale -c "$HS_CONFIG" apikeys create -o json | tr -d '"')"
echo "headscale up at http://127.0.0.1:${HS_PORT}"
```

## 2) Create transient OpenTofu config

```bash
export TOFU_TMPDIR="$(mktemp -d)"

cat > "$TOFU_TMPDIR/main.tf" <<'EOF'
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "= 0.28.0"
    }
  }
}

provider "tailscale" {
  base_url = var.tailscale_base_url
  api_key  = var.tailscale_api_key
  tailnet  = "-"
}

variable "tailscale_api_key" {
  type      = string
  sensitive = true
}

variable "tailscale_base_url" {
  type = string
}

resource "tailscale_tailnet_key" "smoke" {
  reusable      = true
  ephemeral     = false
  preauthorized = true
  expiry        = 3600
  tags          = ["tag:k8s"]
}

output "created_key_id" {
  value = tailscale_tailnet_key.smoke.id
}
EOF
```

## 3) Run smoke lifecycle

```bash
cd "$TOFU_TMPDIR"

tofu init

TF_VAR_tailscale_api_key="$TS_API_KEY" \
TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
tofu apply -auto-approve

# idempotence check: expect exit code 0
TF_VAR_tailscale_api_key="$TS_API_KEY" \
TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
tofu plan -detailed-exitcode

TF_VAR_tailscale_api_key="$TS_API_KEY" \
TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
tofu destroy -auto-approve
```

## 4) Cleanup

```bash
kill "$HS_PID" 2>/dev/null || true
wait "$HS_PID" 2>/dev/null || true

rm -rf "$TOFU_TMPDIR" "$HS_TMPDIR"
unset HS_PORT HS_GRPC_PORT HS_TMPDIR HS_CONFIG HS_SOCKET HS_PID TS_API_KEY TOFU_TMPDIR
```
