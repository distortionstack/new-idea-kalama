"""Docker CLI patch backend with isolated workspaces and explicit strategy routing."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from typing import Any, Mapping

from ..target.models import ImageIdentity, ImageSourceKind, Step2Request
from ..target.victim_manager import (
    CommandRunner, collect_target_facts, ensure_network, wait_until_ready,
)
from .models import PatchAction, PatchStrategy


class DockerPatchError(RuntimeError):
    pass


def _missing(result) -> bool:
    text = f"{result.stdout}\n{result.stderr}".casefold()
    return result.exit_code != 0 and ("no such" in text or "not found" in text)


def _inspect(runner: CommandRunner, kind: str, identity: str) -> Mapping[str, Any]:
    result = runner.run(("docker", kind, "inspect", identity))
    if result.exit_code != 0:
        raise DockerPatchError(f"unable to inspect {kind} {identity!r}")
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, list) or not value or not isinstance(value[0], Mapping):
            raise ValueError
        return value[0]
    except (json.JSONDecodeError, ValueError) as exc:
        raise DockerPatchError(f"invalid docker {kind} inspect response") from exc


def _image_identity(data: Mapping[str, Any], reference: str) -> dict[str, Any]:
    digests = sorted(x for x in data.get("RepoDigests", []) if isinstance(x, str))
    tags = sorted(x for x in data.get("RepoTags", []) if isinstance(x, str))
    return {"reference": reference, "requested_reference": reference,
            "image_id": data.get("Id"), "repo_digests": digests,
            "selected_digest": digests[0] if digests else None, "repo_tags": tags,
            "platform": "/".join(x for x in (data.get("Os"), data.get("Architecture")) if x)}


def _attempt_workspace(base: str, run_id: str, attempt: int) -> str:
    root = base or f"patch-workspace-{run_id}"
    suffix = f"-a{attempt}"
    if root.endswith(suffix):
        return root
    if re.search(r"-a[0-9]+$", root):
        root = re.sub(r"-a[0-9]+$", "", root)
    return f"{root}{suffix}"


def _command_evidence(command: str, operation: str, result) -> dict[str, Any]:
    return {"success": result.exit_code == 0, "exit_code": result.exit_code,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "stdout": result.stdout[-2000:] if result.stdout else None,
            "stderr": result.stderr[-2000:] if result.stderr else None,
            "operation": operation, "execution_target": "patch-workspace"}


class DockerPatchBackend:
    """Production adapter. All host execution remains argv-based with ``shell=False``."""

    def __init__(self, runner: CommandRunner, *, readiness_timeout: float = 30.0):
        self.runner, self.readiness_timeout = runner, readiness_timeout

    def inspect_source(self, source_image: Mapping[str, Any]) -> Mapping[str, Any]:
        identity = str(source_image.get("image_id") or source_image.get("canonical_identity")
                       or source_image.get("requested_reference"))
        return _image_identity(_inspect(self.runner, "image", identity),
                               str(source_image.get("requested_reference") or identity))

    def prepare_workspace(self, plan_artifact: Mapping[str, Any], *, attempt: int = 1) -> Mapping[str, Any]:
        run_id = str(plan_artifact["run_id"])
        name = _attempt_workspace(str(plan_artifact["planned_after"]["patch_workspace"]), run_id, attempt)
        source_id = str(plan_artifact["source_image"].get("image_id")
                        or plan_artifact["source_image"]["canonical_identity"])
        inspected = self.runner.run(("docker", "container", "inspect", name))
        if inspected.exit_code == 0:
            data = _inspect(self.runner, "container", name)
            labels = (data.get("Config") or {}).get("Labels") or {}
            if (labels.get("kalama.managed") != "true"
                    or labels.get("kalama.run_id") != run_id
                    or labels.get("kalama.phase") != "patch"
                    or labels.get("kalama.role") != "patch-workspace"
                    or labels.get("kalama.attempt") != str(attempt)
                    or data.get("Image") != source_id):
                raise DockerPatchError("PATCH_WORKSPACE_CONFLICT")
        elif _missing(inspected):
            args = ("docker", "create", "--name", name,
                    "--label", "kalama.managed=true", "--label", f"kalama.run_id={run_id}",
                    "--label", "kalama.phase=patch", "--label", "kalama.role=patch-workspace",
                    "--label", f"kalama.attempt={attempt}",
                    "--label", f"kalama.source_image_id={source_id}",
                    "--entrypoint", "sh", source_id, "-c", "sleep infinity")
            result = self.runner.run(args)
            if result.exit_code != 0:
                raise DockerPatchError("PATCH_WORKSPACE_CREATE_FAILED")
            data = _inspect(self.runner, "container", name)
        else:
            raise DockerPatchError("PATCH_WORKSPACE_INSPECT_FAILED")
        if not (data.get("State") or {}).get("Running"):
            result = self.runner.run(("docker", "start", name))
            if result.exit_code != 0:
                raise DockerPatchError("PATCH_WORKSPACE_START_FAILED")
        return {"container_name": name, "container_id": data.get("Id"),
                "source_image_id": source_id,
                "labels": {"kalama.managed": "true", "kalama.run_id": run_id,
                           "kalama.phase": "patch", "kalama.role": "patch-workspace",
                           "kalama.attempt": str(attempt)}}

    @staticmethod
    def _package_command(action: PatchAction) -> str | None:
        package = action.package_name
        version = action.candidate.target_version if action.candidate else None
        ecosystem = (action.ecosystem or "").casefold()
        if not package or not version:
            return None
        package_arg, version_arg = shlex.quote(package), shlex.quote(version)
        if ecosystem in {"debian", "ubuntu", "deb"}:
            return f"apt-get update && apt-get install -y -- {package_arg}={version_arg}"
        if ecosystem in {"alpine", "apk"}:
            return f"apk add --no-cache {package_arg}={version_arg}"
        if ecosystem in {"redhat", "centos", "fedora", "rpm"}:
            item = shlex.quote(f"{package}-{version}")
            return f"(command -v dnf >/dev/null && dnf install -y {item}) || yum install -y {item}"
        return None

    def execute_action(self, action: PatchAction, context: Mapping[str, Any],
                       *, timeout: float) -> Mapping[str, Any]:
        workspace = str(context["workspace"]["container_name"])
        if action.strategy == PatchStrategy.PACKAGE_MANAGER:
            command = self._package_command(action)
        elif action.strategy == PatchStrategy.HUMAN_COMMAND:
            if (action.execution or {}).get("execution_target") != "patch-workspace":
                return {"success": False, "code": "HUMAN_COMMAND_TARGET_INVALID"}
            command = (action.execution or {}).get("command")
        else:
            return {"success": False,
                    "code": f"{action.strategy.value}_EXECUTOR_NOT_CONFIGURED"}
        if not command:
            return {"success": False, "code": "PATCH_COMMAND_UNRESOLVED"}
        result = self.runner.run(("docker", "exec", workspace, "sh", "-lc", command),
                                 timeout=timeout)
        return _command_evidence(command, action.strategy.value, result)

    def execute_validation(self, command: str, context: Mapping[str, Any],
                           *, timeout: float) -> Mapping[str, Any]:
        workspace = str(context["workspace"]["container_name"])
        result = self.runner.run(("docker", "exec", workspace, "sh", "-lc", command),
                                 timeout=timeout)
        return _command_evidence(command, "validation", result)

    def finalize_image(self, plan_artifact: Mapping[str, Any],
                       workspace: Mapping[str, Any]) -> Mapping[str, Any]:
        reference = str(plan_artifact["planned_after"]["image_reference"])
        conflict = self.runner.run(("docker", "image", "inspect", reference))
        if conflict.exit_code == 0:
            existing = _inspect(self.runner, "image", reference)
            labels = (existing.get("Config") or {}).get("Labels") or {}
            run_id = str(plan_artifact["run_id"])
            if (labels.get("kalama.managed") != "true"
                    or labels.get("kalama.run_id") != run_id
                    or labels.get("kalama.phase") != "after"):
                raise DockerPatchError("PATCHED_IMAGE_CONFLICT")
            after_name = f"victim-after-{run_id}"
            after = self.runner.run(("docker", "container", "inspect", after_name))
            if after.exit_code == 0:
                data = _inspect(self.runner, "container", after_name)
                after_labels = (data.get("Config") or {}).get("Labels") or {}
                if (after_labels.get("kalama.managed") != "true"
                        or after_labels.get("kalama.run_id") != run_id
                        or after_labels.get("kalama.phase") != "after"):
                    raise DockerPatchError("AFTER_CONTAINER_CONFLICT")
                removed = self.runner.run(("docker", "container", "rm", "-f", after_name))
                if removed.exit_code != 0:
                    raise DockerPatchError("AFTER_CONTAINER_REMOVE_FAILED")
            elif not _missing(after):
                raise DockerPatchError("AFTER_CONTAINER_INSPECT_FAILED")
            removed = self.runner.run(("docker", "image", "rm", reference))
            if removed.exit_code != 0:
                raise DockerPatchError("PATCHED_IMAGE_REMOVE_FAILED")
        if not _missing(conflict):
            if conflict.exit_code != 0:
                raise DockerPatchError("PATCHED_IMAGE_INSPECT_FAILED")
        run_id = str(plan_artifact["run_id"])
        source = _inspect(self.runner, "image", str(workspace["source_image_id"]))
        source_config = source.get("Config") or {}
        entrypoint = source_config.get("Entrypoint") or []
        command = source_config.get("Cmd") or []
        result = self.runner.run(("docker", "commit",
            "--change", "LABEL kalama.managed=true",
            "--change", f"LABEL kalama.run_id={run_id}",
            "--change", "LABEL kalama.phase=after",
            "--change", f"LABEL kalama.source_image_id={workspace['source_image_id']}",
            "--change", f"ENTRYPOINT {json.dumps(entrypoint, separators=(',', ':'))}",
            "--change", f"CMD {json.dumps(command, separators=(',', ':'))}",
            str(workspace["container_name"]), reference))
        if result.exit_code != 0:
            raise DockerPatchError("PATCHED_IMAGE_CREATE_FAILED")
        return _image_identity(_inspect(self.runner, "image", reference), reference)

    def resolve_prebuilt_image(self, action: PatchAction,
                               plan_artifact: Mapping[str, Any]) -> Mapping[str, Any]:
        selected = action.candidate.source_identifier if action.candidate else None
        if not selected:
            return {"success": False, "code": "PREBUILT_IMAGE_UNRESOLVED"}
        try:
            data = _inspect(self.runner, "image", selected)
        except DockerPatchError as exc:
            return {"success": False, "code": "PREBUILT_IMAGE_NOT_FOUND", "message": str(exc)}
        reference = str(plan_artifact["planned_after"]["image_reference"])
        conflict = self.runner.run(("docker", "image", "inspect", reference))
        if conflict.exit_code == 0:
            return {"success": False, "code": "PATCHED_IMAGE_CONFLICT"}
        tagged = self.runner.run(("docker", "tag", str(data.get("Id")), reference))
        if tagged.exit_code != 0:
            return {"success": False, "code": "PREBUILT_IMAGE_TAG_FAILED"}
        return {"success": True,
                "image_identity": _image_identity(_inspect(self.runner, "image", reference), reference)}

    def verify_source_preserved(self, source_identity: Mapping[str, Any]) -> bool:
        image_id = source_identity.get("image_id")
        if not image_id:
            return False
        try:
            return _inspect(self.runner, "image", str(image_id)).get("Id") == image_id
        except DockerPatchError:
            return False

    def create_after_target(self, run_id: str, patched_image: Mapping[str, Any],
                            planned_after: Mapping[str, Any],
                            before_facts: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        ensure_network("kalama-net", self.runner)
        name = f"victim-after-{run_id}"
        image_id = str(patched_image["image_id"])
        inspected = self.runner.run(("docker", "container", "inspect", name))
        if inspected.exit_code == 0:
            data = _inspect(self.runner, "container", name)
            labels = (data.get("Config") or {}).get("Labels") or {}
            if (labels.get("kalama.managed") != "true" or labels.get("kalama.run_id") != run_id
                    or labels.get("kalama.phase") != "after" or data.get("Image") != image_id):
                raise DockerPatchError("AFTER_CONTAINER_CONFLICT")
        elif _missing(inspected):
            args = ["docker", "create", "--name", name,
                    "--label", "kalama.managed=true", "--label", f"kalama.run_id={run_id}",
                    "--label", "kalama.phase=after", "--label", "kalama.role=victim-after",
                    "--network", "kalama-net"]
            for environment in before_facts.get("environment") or ():
                args += ["--env", str(environment)]
            for port in before_facts.get("published_ports") or ():
                if not isinstance(port, Mapping) or not port.get("container_port"):
                    continue
                container_port = f"{port['container_port']}/{port.get('protocol', 'tcp')}"
                # The before victim remains alive; Docker chooses a fresh host port.
                args += ["--publish", container_port]
            entrypoint = before_facts.get("entrypoint") or ()
            # An explicit empty value clears a workspace-derived image entrypoint.
            args += ["--entrypoint", str(entrypoint[0]) if entrypoint else ""]
            args.append(image_id)
            args.extend(str(x) for x in before_facts.get("command") or ())
            created = self.runner.run(tuple(args))
            if created.exit_code != 0:
                raise DockerPatchError("AFTER_CONTAINER_CREATE_FAILED")
            data = _inspect(self.runner, "container", name)
        else:
            raise DockerPatchError("AFTER_CONTAINER_INSPECT_FAILED")
        if not (data.get("State") or {}).get("Running"):
            started = self.runner.run(("docker", "start", name))
            if started.exit_code != 0:
                raise DockerPatchError("AFTER_CONTAINER_START_FAILED")
        ready = wait_until_ready(name, self.runner, self.readiness_timeout)
        identity = ImageIdentity(str(patched_image["reference"]), image_id,
                                 tuple(patched_image.get("repo_digests") or ()),
                                 patched_image.get("selected_digest"),
                                 tuple(patched_image.get("repo_tags") or ()),
                                 patched_image.get("platform"), ImageSourceKind.LOCAL_BUILT)
        request = Step2Request(run_id, str(patched_image["reference"]), "",
                               phase="after", environment=(), command=())
        facts = collect_target_facts(
            request, identity, ready, self.runner, container_name=name).to_dict()
        return identity.to_dict(), facts
