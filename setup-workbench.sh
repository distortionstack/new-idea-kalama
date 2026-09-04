#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
network_name="kalama-net"
workbench_name="${KALAMA_WORKBENCH_NAME:-kalama-workbench-modern}"
workbench_image="${KALAMA_WORKBENCH_IMAGE:-docker:27-cli}"
trivy_version="${KALAMA_TRIVY_VERSION:-0.74.0}"
container_name="msf-resolver-host"
msf_image="${KALAMA_MSF_IMAGE:-metasploitframework/metasploit-framework:latest}"
msf_data="${HOME}/.msf4"

if ! command -v docker >/dev/null 2>&1; then
  echo "DOCKER_CLI_MISSING: install Docker Engine before running setup" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "DOCKER_DAEMON_UNREACHABLE: start Docker and verify permissions" >&2
  exit 1
fi
network_error=""
if network_error="$(docker network inspect "${network_name}" 2>&1)"; then
  echo "Reusing Docker network ${network_name}"
elif [[ "${network_error}" == *"not found"* || "${network_error}" == *"No such network"* ]]; then
  docker network create --label kalama.managed=true "${network_name}" >/dev/null
  echo "Created Docker network ${network_name}"
else
  echo "KALAMA_NETWORK_CONFLICT: unable to inspect ${network_name}: ${network_error}" >&2
  exit 1
fi

workbench_error=""
if workbench_error="$(docker container inspect "${workbench_name}" 2>&1)"; then
  workbench_existing_image="$(docker inspect -f '{{.Config.Image}}' "${workbench_name}")"
  workbench_managed="$(docker inspect -f '{{index .Config.Labels "kalama.managed"}}' "${workbench_name}")"
  workbench_role="$(docker inspect -f '{{index .Config.Labels "kalama.role"}}' "${workbench_name}")"
  socket_source="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}{{.Source}}{{end}}{{end}}' "${workbench_name}")"
  if [[ "${workbench_existing_image}" != "${workbench_image}" || "${workbench_managed}" != "true" || "${workbench_role}" != "workbench" || "${socket_source}" != "/var/run/docker.sock" ]]; then
    echo "WORKBENCH_CONTAINER_CONFLICT: ${workbench_name} has incompatible image, labels, or Docker socket mount" >&2
    exit 1
  fi
  workbench_network="$(docker inspect -f '{{with index .NetworkSettings.Networks "kalama-net"}}{{.NetworkID}}{{end}}' "${workbench_name}")"
  if [[ -z "${workbench_network}" ]]; then
    docker network connect "${network_name}" "${workbench_name}"
  fi
  workbench_running="$(docker inspect -f '{{.State.Running}}' "${workbench_name}")"
  if [[ "${workbench_running}" != "true" ]]; then
    docker start "${workbench_name}" >/dev/null
  fi
  echo "Reusing scanner workbench ${workbench_name}"
elif [[ "${workbench_error}" == *"No such container"* || "${workbench_error}" == *"not found"* ]]; then
  docker run -d \
    --name "${workbench_name}" \
    --label kalama.managed=true \
    --label kalama.role=workbench \
    --label kalama.component=workbench \
    --network "${network_name}" \
    --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
    --entrypoint sh \
    "${workbench_image}" -c 'tail -f /dev/null' >/dev/null
  echo "Created scanner workbench ${workbench_name}"
else
  echo "WORKBENCH_CONTAINER_CONFLICT: unable to inspect ${workbench_name}: ${workbench_error}" >&2
  exit 1
fi

docker exec -e "TRIVY_VERSION=${trivy_version}" "${workbench_name}" sh -ec '
  if command -v trivy >/dev/null 2>&1 && trivy --version | grep -F "Version: ${TRIVY_VERSION}" >/dev/null; then
    exit 0
  fi
  apk add --no-cache curl tar >/dev/null
  case "$(uname -m)" in
    x86_64) archive_arch="64bit" ;;
    aarch64|arm64) archive_arch="ARM64" ;;
    *) echo "WORKBENCH_ARCH_UNSUPPORTED: $(uname -m)" >&2; exit 1 ;;
  esac
  archive="trivy_${TRIVY_VERSION}_Linux-${archive_arch}.tar.gz"
  checksums="trivy_${TRIVY_VERSION}_checksums.txt"
  release="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
  temporary="$(mktemp -d)"
  trap '\''rm -rf "${temporary}"'\'' EXIT
  curl --fail --silent --show-error --location "${release}/${archive}" --output "${temporary}/${archive}"
  curl --fail --silent --show-error --location "${release}/${checksums}" --output "${temporary}/${checksums}"
  expected="$(grep -E "[[:space:]]${archive}$" "${temporary}/${checksums}" || true)"
  if [ -z "${expected}" ]; then
    echo "TRIVY_CHECKSUM_MISSING: ${archive}" >&2
    exit 1
  fi
  printf "%s\n" "${expected}" > "${temporary}/selected.checksum"
  if ! (cd "${temporary}" && sha256sum -c selected.checksum >/dev/null); then
    echo "TRIVY_CHECKSUM_MISMATCH: ${archive}" >&2
    exit 1
  fi
  tar -xzf "${temporary}/${archive}" -C /usr/local/bin trivy
  chmod 0755 /usr/local/bin/trivy
'

docker exec "${workbench_name}" docker info --format '{{.ServerVersion}}' >/dev/null
docker exec "${workbench_name}" trivy --version

mkdir -p "${msf_data}"
container_error=""
if container_error="$(docker container inspect "${container_name}" 2>&1)"; then
  existing_image="$(docker inspect -f '{{.Config.Image}}' "${container_name}")"
  mount_source="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/root/.msf4"}}{{.Source}}{{end}}{{end}}' "${container_name}")"
  if [[ "${existing_image}" != "${msf_image}" || "${mount_source}" != "${msf_data}" ]]; then
    echo "MSF_RESOLVER_CONTAINER_CONFLICT: ${container_name} has incompatible image or mount" >&2
    exit 1
  fi
  network_id="$(docker inspect -f '{{with index .NetworkSettings.Networks "kalama-net"}}{{.NetworkID}}{{end}}' "${container_name}")"
  if [[ -z "${network_id}" ]]; then
    docker network connect "${network_name}" "${container_name}"
  fi
  running="$(docker inspect -f '{{.State.Running}}' "${container_name}")"
  if [[ "${running}" != "true" ]]; then
    docker start "${container_name}" >/dev/null
  fi
  echo "Reusing Metasploit container ${container_name}"
elif [[ "${container_error}" == *"No such container"* || "${container_error}" == *"not found"* ]]; then
  docker run -d \
    --name "${container_name}" \
    --label kalama.managed=true \
    --network "${network_name}" \
    --mount "type=bind,source=${msf_data},target=/root/.msf4" \
    "${msf_image}" tail -f /dev/null >/dev/null
  echo "Created Metasploit container ${container_name}"
else
  echo "MSF_RESOLVER_CONTAINER_CONFLICT: unable to inspect ${container_name}: ${container_error}" >&2
  exit 1
fi

mkdir -p "${repo_root}/output/state"
python_command="${KALAMA_PYTHON:-${repo_root}/.venv/bin/python}"
if [[ ! -x "${python_command}" ]]; then
  python_command="$(command -v python3)"
fi

"${python_command}" -m kalama --output-root "${repo_root}/output" doctor
