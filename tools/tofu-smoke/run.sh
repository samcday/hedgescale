#!/usr/bin/env bash

set -euo pipefail

KEEP_TMP=0
PROVIDER_VERSION="0.28.0"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--keep)
		KEEP_TMP=1
		shift
		;;
	--provider-version)
		if [[ $# -lt 2 ]]; then
			echo "--provider-version requires a value"
			exit 2
		fi
		PROVIDER_VERSION="$2"
		shift 2
		;;
	-h | --help)
		echo "Usage: $0 [--keep] [--provider-version <version>]"
		echo ""
		echo "Runs a local SQLite headscale + OpenTofu tailscale_tailnet_key smoke test."
		echo ""
		echo "Options:"
		echo "  --keep                         keep temporary directories"
		echo "  --provider-version <version>   tailscale provider version (default: ${PROVIDER_VERSION})"
		exit 0
		;;
	*)
		echo "Unknown argument: $1"
		echo "Use --help for usage."
		exit 2
		;;
	esac
done

if command -v python3 >/dev/null 2>&1; then
	PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
	PYTHON_BIN="python"
else
	echo "python3 or python is required"
	exit 1
fi

for bin in go tofu; do
	if ! command -v "$bin" >/dev/null 2>&1; then
		echo "Missing required binary: $bin"
		exit 1
	fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

pick_port() {
	"${PYTHON_BIN}" - <<'PY'
import socket

s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

HS_PORT="$(pick_port)"
HS_GRPC_PORT="$(pick_port)"
HS_TMPDIR="$(mktemp -d)"
TOFU_TMPDIR="$(mktemp -d)"
HS_CONFIG="${HS_TMPDIR}/config.yaml"
HS_SOCKET="${HS_TMPDIR}/headscale.sock"
HS_LOG="${HS_TMPDIR}/server.log"
HS_BIN="${HS_TMPDIR}/headscale"

HS_PID=""
TS_API_KEY=""
TF_APPLIED=0
RUN_OK=0

cleanup() {
	status=$?

	if [[ "${TF_APPLIED}" -eq 1 ]]; then
		echo "==> Destroying OpenTofu resources"
		(
			cd "${TOFU_TMPDIR}"
			TF_VAR_tailscale_api_key="${TS_API_KEY}" \
				TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
				tofu destroy -auto-approve >/dev/null 2>&1 || true
		)
	fi

	if [[ -n "${HS_PID}" ]] && kill -0 "${HS_PID}" >/dev/null 2>&1; then
		kill "${HS_PID}" >/dev/null 2>&1 || true
		wait "${HS_PID}" >/dev/null 2>&1 || true
	fi

	if [[ "${RUN_OK}" -eq 1 && "${KEEP_TMP}" -eq 0 ]]; then
		echo "Temporary artifacts removed (rerun with --keep to retain logs/db/state)."
		rm -rf "${HS_TMPDIR}" "${TOFU_TMPDIR}"
	else
		echo ""
		echo "Artifacts kept for inspection:"
		echo "  HS_TMPDIR=${HS_TMPDIR}"
		echo "  TOFU_TMPDIR=${TOFU_TMPDIR}"
		echo "  headscale log: ${HS_LOG}"
	fi

	exit "${status}"
}

trap cleanup EXIT

echo "==> Building headscale binary"
(
	cd "${REPO_ROOT}"
	go build -o "${HS_BIN}" ./cmd/headscale
)

cat >"${HS_CONFIG}" <<EOF
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

echo "==> Starting headscale on http://127.0.0.1:${HS_PORT}"
"${HS_BIN}" -c "${HS_CONFIG}" serve >"${HS_LOG}" 2>&1 &
HS_PID=$!

echo "==> Waiting for headscale socket"
for _ in $(seq 1 120); do
	if [[ -S "${HS_SOCKET}" ]]; then
		break
	fi

	if ! kill -0 "${HS_PID}" >/dev/null 2>&1; then
		echo "headscale exited before becoming ready"
		echo "--- headscale log ---"
		cat "${HS_LOG}"
		exit 1
	fi

	sleep 0.5
done

if [[ ! -S "${HS_SOCKET}" ]]; then
	echo "headscale socket did not appear in time"
	echo "--- headscale log ---"
	cat "${HS_LOG}"
	exit 1
fi

echo "==> Creating bootstrap API key"
TS_API_KEY="$("${HS_BIN}" -c "${HS_CONFIG}" apikeys create -o json | tr -d '"')"
if [[ -z "${TS_API_KEY}" ]]; then
	echo "failed to create API key"
	exit 1
fi

cat >"${TOFU_TMPDIR}/main.tf" <<EOF
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "= ${PROVIDER_VERSION}"
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

echo "==> OpenTofu init"
(
	cd "${TOFU_TMPDIR}"
	tofu init
)

echo "==> OpenTofu apply"
(
	cd "${TOFU_TMPDIR}"
	TF_VAR_tailscale_api_key="${TS_API_KEY}" \
		TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
		tofu apply -auto-approve
)
TF_APPLIED=1

CREATED_KEY_ID=""
if CREATED_KEY_ID="$(cd "${TOFU_TMPDIR}" && tofu output -raw created_key_id 2>/dev/null)"; then
	echo "==> Created tailnet key id: ${CREATED_KEY_ID}"
fi

if command -v sqlite3 >/dev/null 2>&1; then
	echo "==> SQLite snapshot after apply (pre_auth_keys)"
	sqlite3 "${HS_TMPDIR}/headscale.sqlite" "select id, reusable, ephemeral, used, expiration from pre_auth_keys order by id;" || true
fi

echo "==> OpenTofu idempotence check (plan -detailed-exitcode)"
set +e
(
	cd "${TOFU_TMPDIR}"
	TF_VAR_tailscale_api_key="${TS_API_KEY}" \
		TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
		tofu plan -detailed-exitcode
)
PLAN_EXIT=$?
set -e

if [[ "${PLAN_EXIT}" -eq 1 ]]; then
	echo "OpenTofu plan failed"
	exit 1
fi

if [[ "${PLAN_EXIT}" -eq 2 ]]; then
	echo "OpenTofu reported drift (expected idempotent plan exit 0)"
	exit 1
fi

echo "==> OpenTofu destroy"
(
	cd "${TOFU_TMPDIR}"
	TF_VAR_tailscale_api_key="${TS_API_KEY}" \
		TF_VAR_tailscale_base_url="http://127.0.0.1:${HS_PORT}" \
		tofu destroy -auto-approve
)
TF_APPLIED=0

if command -v sqlite3 >/dev/null 2>&1; then
	echo "==> SQLite snapshot after destroy (pre_auth_keys count)"
	sqlite3 "${HS_TMPDIR}/headscale.sqlite" "select count(*) from pre_auth_keys;" || true
fi

RUN_OK=1

echo ""
echo "Smoke test passed"
echo "  headscale base_url: http://127.0.0.1:${HS_PORT}"
echo "  provider version: ${PROVIDER_VERSION}"
