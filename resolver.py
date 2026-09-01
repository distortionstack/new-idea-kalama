#!/usr/bin/env python3
"""
Kalama Resolver MVP.

Standalone, read-only lookup: given a CVE-ID, find candidate Metasploit
modules and their declared options. Does not execute, check, or configure
anything. Does not touch src/app/kalama/ or any attack/patch/cve_meta config.

resolver.py itself runs on the host. Metasploit only exists inside a
persistent Docker container (msfconsole is not on the host $PATH), so every
msfconsole invocation is routed through `docker exec` into that container.
The container is expected to already be running (see ensure_container_running
for the one-time `docker run` setup command).

Usage:
    python resolver.py run --cve CVE-2017-5638 [--msf-container NAME]
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys

import yaml  # batch/review file I/O and ground-truth reads (draft_config.py)

from resolver_core import DiscoveryBackend, discover_cve
from resolver_models import DiscoveryStatus

# The modules_metadata.json cache is read straight from the HOST path, not
# via docker exec: the container is expected to be started with
# `-v ~/.msf4:/root/.msf4`, so the host and container see the identical file.
# Reading it directly avoids an extra docker exec round-trip per lookup.
MSF_METADATA_CACHE = os.path.expanduser("~/.msf4/store/modules_metadata.json")

DEFAULT_MSF_CONTAINER = os.environ.get("MSF_RESOLVER_CONTAINER", "msf-resolver-host")
MSF_TIMEOUT_SECONDS = 240
DOCKER_TIMEOUT_SECONDS = 20
JSON_SENTINEL_START = "===KALAMA_RESOLVER_JSON_START==="
JSON_SENTINEL_END = "===KALAMA_RESOLVER_JSON_END==="

MODULE_PATH_RE = re.compile(r"^(exploit|auxiliary|post|payload|encoder|nop)/")

# Msf::RankingName, mirrored here because modules_metadata.json stores rank
# as the raw integer, not the string msfconsole displays.
RANK_NAMES = {
    0: "manual", 100: "low", 200: "average", 300: "normal",
    400: "good", 500: "great", 600: "excellent",
}

# --------------------------------------------------------------------------
# Draft-config logic (shared by draft_config.py's ground-truth diff and the
# batch/review CLI below). Facts a `scan` stage would already have.
# target_ip/msf_ip mirror the attack/ ground truth's own runtime-templating
# convention ("{target_ip}", "{msf_ip}") when no concrete value is supplied.
# --------------------------------------------------------------------------

DEFAULT_FACTS = {
    "target_ip": "{target_ip}",
    "target_port": 9200,
    "msf_ip": "{msf_ip}",
}

# Module option name -> which scan fact fills it, independent of whether the
# module even declares that option itself (LHOST is a payload-datastore
# field, not part of the exploit module's own OptionContainer -- see below).
FACT_FOR_OPTION = {
    "RHOSTS": "target_ip",
    "RPORT": "target_port",
    "LHOST": "msf_ip",
}

# Ground-truth exploit.params keys confirmed genuinely absent from the
# module's own declared option schema (mod.options) -- confirmed empirically
# against exploit/multi/elasticsearch/search_groovy_script:
# mod.options.key?("PAYLOAD") is false, mod.datastore["PAYLOAD"] is nil.
# These belong to whichever payload gets selected, not to the exploit module
# itself. Per spec: do not guess a value for these.
NOT_IN_MODULE_SCHEMA = {"PAYLOAD"}

# --------------------------------------------------------------------------
# Confidence tiers for the batch/review CLI, based on empirical results
# across the 3 live-tested CVEs (CVE-2015-1427, CVE-2017-5638, CVE-2017-9805)
# -- see conversation history / lab notes for the individual test reports.
# --------------------------------------------------------------------------

TIER_AUTO_VERIFIED = "auto-verified"
TIER_AUTO_UNVERIFIED = "auto-unverified"
TIER_USER_REQUIRED = "user-required"

# Fact-derived fields that matched ground truth / worked correctly in all 3
# live tests. Pre-filled, not blocking; user can override but doesn't have to.
FACT_VERIFIED_FIELDS = {"RHOSTS", "RPORT", "LHOST"}

# TARGETURI's module-declared default was right for one live CVE and wrong
# (404, confirmed by a live reachability probe) for the other two -- not
# reliable enough to trust blindly, but not so unreliable that guessing is
# useless either. Flagged distinctly so the human double-checks it every
# time rather than assuming it's as safe as the fact-derived fields.
UNVERIFIED_FIELDS = {"TARGETURI"}

# No mechanism in module metadata to determine these at all. PAYLOAD is
# conditionally promotable to auto-unverified via live interpreter recon
# (see attempt_interpreter_recon) once a target is actually reachable --
# batch-generation time has no target up yet, so it always starts here.
STRUCTURALLY_USER_REQUIRED_FIELDS = {"PAYLOAD", "LPORT"}


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def normalize_cve(raw):
    cve = raw.strip().upper()
    if not cve.startswith("CVE-"):
        cve = "CVE-" + cve
    m = re.match(r"^CVE-(\d{4})-(\d{4,7})$", cve)
    if not m:
        return None
    return cve


def cve_match_variants(cve_id):
    m = re.match(r"^CVE-(\d{4})-(\d{4,7})$", cve_id)
    year, num = m.groups()
    return {cve_id, f"{year}-{num}"}


# --------------------------------------------------------------------------
# Step 1/2: candidate discovery + base metadata, JSON cache path
# --------------------------------------------------------------------------

def load_json_cache(path=MSF_METADATA_CACHE):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        eprint(f"[resolver] warning: could not parse {path}: {e}")
        return None


def references_as_list(raw_refs):
    if raw_refs is None:
        return []
    if isinstance(raw_refs, list):
        return [str(r) for r in raw_refs]
    if isinstance(raw_refs, dict):
        return [f"{k}-{v}" for k, v in raw_refs.items()]
    return [str(raw_refs)]


def find_candidates_from_cache(cache, cve_id):
    """Returns {fullname: metadata_dict} using only the JSON cache's fields.

    NOTE: the cache's own dict keys are NOT module fullnames (confirmed
    empirically against a real modules_metadata.json) -- e.g. the key
    "exploit_multi/http/struts2_content_type_ognl" underscores the type
    instead of slashing it. The real, usable fullname
    ("exploit/multi/http/struts2_content_type_ognl") is in each entry's own
    "fullname" field, which is what must be passed to
    framework.modules.create(...) later. Entries without a usable fullname
    are skipped rather than guessed at.
    """
    if not cache:
        return {}
    variants = cve_match_variants(cve_id)
    found = {}
    for cache_key, entry in cache.items():
        if not isinstance(entry, dict):
            continue
        refs = references_as_list(entry.get("references"))
        refs_upper = [r.upper() for r in refs]
        if not any(v in r for r in refs_upper for v in variants):
            continue

        fullname = entry.get("fullname")
        if not fullname or not MODULE_PATH_RE.match(fullname):
            eprint(f"[resolver] warning: cache entry '{cache_key}' has no usable fullname; skipping.")
            continue

        rank_raw = entry.get("rank")
        if isinstance(rank_raw, int):
            rank = RANK_NAMES.get(rank_raw, str(rank_raw))
        elif rank_raw:
            rank = str(rank_raw).lower()
        else:
            rank = "normal"

        disclosure_date = entry.get("disclosure_date") or None
        if disclosure_date is not None:
            # cache stores a full timestamp, e.g. "2017-03-07 00:00:00 +0000"
            disclosure_date = str(disclosure_date).split(" ")[0]

        platform_raw = entry.get("platform")
        if isinstance(platform_raw, str):
            platform = [p.strip() for p in platform_raw.split(",") if p.strip()]
        elif isinstance(platform_raw, list):
            platform = [str(p) for p in platform_raw]
        else:
            platform = []

        targets_raw = entry.get("targets")
        if isinstance(targets_raw, dict):
            targets = sorted(targets_raw.keys(), key=lambda k: targets_raw[k])
        elif isinstance(targets_raw, list):
            targets = [str(t) for t in targets_raw]
        else:
            targets = []

        check_supported = bool(entry.get("check", False))

        found[fullname] = {
            "rank": rank,
            "disclosure_date": disclosure_date,
            "platform": platform,
            "targets": targets,
            "check_supported": check_supported,
            "references": refs,
        }
    return found


# --------------------------------------------------------------------------
# Docker transport: msfconsole only exists inside a persistent container.
# A missing/stopped container is a setup problem and must fail loudly — it
# must never quietly collapse into "found: false", same discipline as the
# earlier missing-msfconsole-binary fix.
# --------------------------------------------------------------------------

def ensure_container_running(container):
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        raise RuntimeError("docker not found in PATH. Install Docker or ensure it's on PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker inspect timed out checking container '{container}'.")

    if proc.returncode != 0:
        raise RuntimeError(
            f"Docker container '{container}' does not exist. Start it first:\n"
            f"  docker run -d --name {container} -v ~/.msf4:/root/.msf4 "
            f"metasploitframework/metasploit-framework:latest tail -f /dev/null"
        )
    if proc.stdout.strip() != "true":
        raise RuntimeError(
            f"Docker container '{container}' exists but is not running. Start it with:\n"
            f"  docker start {container}"
        )


_msfconsole_bin_cache = {}


def get_msfconsole_binary(container):
    """Locate the msfconsole executable inside the container.

    Confirmed empirically against metasploitframework/metasploit-framework:latest:
    msfconsole is NOT on $PATH for `docker exec` sessions (only the image's
    entrypoint script puts it there), so a bare `docker exec ... msfconsole`
    fails with "executable file not found in $PATH". Resolve it via the
    image's $APP_HOME env var instead of hardcoding an internal path, with a
    couple of static fallbacks. Cached per container for this process.
    """
    if container in _msfconsole_bin_cache:
        return _msfconsole_bin_cache[container]

    try:
        which = subprocess.run(
            ["docker", "exec", container, "sh", "-c", "command -v msfconsole"],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
        if which.returncode == 0 and which.stdout.strip():
            _msfconsole_bin_cache[container] = which.stdout.strip()
            return _msfconsole_bin_cache[container]

        app_home = subprocess.run(
            ["docker", "exec", container, "sh", "-c", "echo $APP_HOME"],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        ).stdout.strip()
        for candidate_dir in filter(None, [app_home, "/usr/src/metasploit-framework"]):
            candidate = f"{candidate_dir}/msfconsole"
            check = subprocess.run(
                ["docker", "exec", container, "test", "-x", candidate],
                capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
            )
            if check.returncode == 0:
                _msfconsole_bin_cache[container] = candidate
                return candidate
    except FileNotFoundError:
        raise RuntimeError("docker not found in PATH. Install Docker or ensure it's on PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker exec timed out resolving msfconsole path (container '{container}').")

    raise RuntimeError(
        f"Could not locate msfconsole inside container '{container}' "
        f"(not on $PATH, not at $APP_HOME/msfconsole, not at the default install path)."
    )


# --------------------------------------------------------------------------
# Fallback: msfconsole text search (only when the JSON cache is unavailable)
# --------------------------------------------------------------------------

def find_candidates_via_msfconsole_search(cve_id, container):
    ensure_container_running(container)
    msfconsole_bin = get_msfconsole_binary(container)
    cmd = [
        "docker", "exec", "-i", container,
        msfconsole_bin, "-q", "-n", "-x", f"search cve:{cve_id}; exit",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=MSF_TIMEOUT_SECONDS
        )
    except FileNotFoundError:
        raise RuntimeError("docker not found in PATH. Install Docker or ensure it's on PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker exec msfconsole search timed out (container '{container}').")

    if proc.returncode != 0:
        raise RuntimeError(
            f"docker exec into container '{container}' failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:500]}"
        )

    fullnames = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if not parts[0].isdigit():
            continue
        if MODULE_PATH_RE.match(parts[1]):
            if parts[1] not in fullnames:
                fullnames.append(parts[1])
    return fullnames


# --------------------------------------------------------------------------
# Step 2 (fallback metadata) + Step 3 (options): always via msfconsole,
# batched into a single invocation using the module object model directly
# (mod.options / opt.type), the same primitives msfrpcd's module.options
# call uses, instead of regex-scraping `show options` console tables.
# --------------------------------------------------------------------------

RUBY_TEMPLATE = r"""
<ruby>
require 'json'
fullnames = __FULLNAMES_JSON__
results = {}
fullnames.each do |fullname|
  begin
    mod = framework.modules.create(fullname)
    if mod.nil?
      results[fullname] = {"error" => "could_not_instantiate"}
      next
    end

    rank_name = nil
    begin
      rank_name = Msf::RankingName[mod.rank]
    rescue
      rank_name = nil
    end
    rank_name ||= mod.rank.to_s

    disclosure = nil
    begin
      if mod.disclosure_date
        disclosure = mod.disclosure_date.respond_to?(:strftime) ? mod.disclosure_date.strftime('%Y-%m-%d') : mod.disclosure_date.to_s
      end
    rescue
      disclosure = nil
    end

    platform = []
    begin
      platform = mod.platform.platforms.map(&:realname)
    rescue
      platform = []
    end

    targets = []
    target_details = []
    begin
      targets = mod.targets ? mod.targets.map(&:name) : []
      target_details = mod.targets ? mod.targets.each_with_index.map { |target, index| {"index" => index, "name" => target.name} } : []
    rescue
      targets = []
      target_details = []
    end

    default_target_index = nil
    begin
      raw_default = mod.respond_to?(:default_target) ? mod.default_target : nil
      raw_default = mod.datastore['TARGET'] if raw_default.nil?
      default_target_index = Integer(raw_default) unless raw_default.nil?
    rescue
      default_target_index = nil
    end

    check_supported = false
    begin
      check_supported = mod.has_check?
    rescue
      check_supported = false
    end

    refs = []
    begin
      refs = mod.references.map { |r| r.to_s }
    rescue
      refs = []
    end

    opts = []
    begin
      mod.options.each_pair do |oname, opt|
        opt_type = nil
        begin
          opt_type = opt.type.to_s
        rescue
          opt_type = opt.class.to_s
        end
        opts << {
          "name" => oname,
          "type" => opt_type,
          "required" => (opt.required ? true : false),
          "default" => opt.default
        }
      end
    rescue => e
      opts = []
    end


    payload_status = "UNAVAILABLE"
    payloads = []
    begin
      compatible = mod.compatible_payloads
      payload_status = compatible.empty? ? "NONE" : "FOUND"
      seen_payloads = {}
      compatible.each do |raw_payload|
        payload_name = raw_payload.is_a?(Array) ? raw_payload[0].to_s : raw_payload.to_s
        payload_name = payload_name.sub(/^payload\//, '')
        next if payload_name.empty? || seen_payloads[payload_name]
        seen_payloads[payload_name] = true
        payloads << {"name" => payload_name}
      end
    rescue => e
      payload_status = "ERROR"
      payloads = []
    end

    results[fullname] = {
      "rank" => rank_name.to_s.downcase,
      "disclosure_date" => disclosure,
      "platform" => platform,
      "targets" => targets,
      "target_details" => target_details,
      "default_target_index" => default_target_index,
      "check_supported" => (check_supported ? true : false),
      "references" => refs,
      "options" => opts,
      "status" => payload_status,
      "payloads" => payloads
    }
  rescue => e
    results[fullname] = {"error" => e.message}
  end
end

puts "__START__"
puts JSON.generate(results)
puts "__END__"
</ruby>
exit -y
"""


CONTAINER_SCRIPT_PATH = "/tmp/kalama_resolver_script.rc"

PAYLOAD_RUBY_TEMPLATE = r"""
<ruby>
require 'json'
module_name = __MODULE_JSON__
payload_name = __PAYLOAD_JSON__
result = {"name" => payload_name, "options" => []}
begin
  mod = framework.modules.create(module_name)
  compatible = mod ? mod.compatible_payloads.map { |item| (item.is_a?(Array) ? item[0] : item).to_s.sub(/^payload\//, '') } : []
  raise "payload_not_compatible" unless compatible.include?(payload_name)
  payload = framework.payloads.create(payload_name)
  raise "payload_not_found" if payload.nil?
  payload.options.each_pair do |oname, opt|
    result["options"] << {"name" => oname,
      "type" => (begin opt.type.to_s rescue opt.class.to_s end),
      "required" => (opt.required ? true : false), "default" => opt.default}
  end
rescue => e
  result = {"error" => e.message}
end
puts "__START__"
puts JSON.generate(result)
puts "__END__"
</ruby>
exit -y
"""


def query_msfconsole_for_modules(fullnames, container):
    """Runs one batched msfconsole resource script for all fullnames, inside
    the persistent Docker container.

    The container has no view of the host filesystem (other than the
    ~/.msf4 volume mount), so the resource script can't be written to a host
    tempfile and referenced by path as before. `resource /dev/stdin` doesn't
    work either -- confirmed empirically that msfconsole's `resource` command
    rejects it with "not a valid resource file" because piped stdin isn't a
    regular file. Instead, the script is written to a real file inside the
    container's own filesystem (via `docker exec ... sh -c 'cat > path'`),
    then loaded from there with `-r`, then removed.

    Returns {fullname: {..metadata.., "options": [...]}} on success, entries
    may contain {"error": "..."} instead if a given module failed to load.
    Raises RuntimeError on total failure (docker/container/timeout/crash).
    """
    if not fullnames:
        return {}

    script_body = (
        RUBY_TEMPLATE
        .replace("__FULLNAMES_JSON__", json.dumps(fullnames))
        .replace("__START__", JSON_SENTINEL_START)
        .replace("__END__", JSON_SENTINEL_END)
    )

    ensure_container_running(container)
    msfconsole_bin = get_msfconsole_binary(container)

    try:
        write_proc = subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-c", f"cat > {CONTAINER_SCRIPT_PATH}"],
            input=script_body, capture_output=True, text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        raise RuntimeError("docker not found in PATH. Install Docker or ensure it's on PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker exec timed out writing resource script (container '{container}').")
    if write_proc.returncode != 0:
        raise RuntimeError(
            f"Failed to write resource script into container '{container}' "
            f"(exit {write_proc.returncode}): {write_proc.stderr.strip()[:500]}"
        )

    cmd = [
        "docker", "exec", "-i", container,
        msfconsole_bin, "-q", "-n", "-r", CONTAINER_SCRIPT_PATH,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=MSF_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"docker exec msfconsole timed out while extracting module data "
            f"(container '{container}')."
        )
    finally:
        subprocess.run(
            ["docker", "exec", container, "rm", "-f", CONTAINER_SCRIPT_PATH],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )

    if proc.returncode != 0:
        raise RuntimeError(
            f"docker exec into container '{container}' failed (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:500]}"
        )

    stdout = proc.stdout
    if JSON_SENTINEL_START not in stdout or JSON_SENTINEL_END not in stdout:
        tail = "\n".join(stdout.splitlines()[-30:])
        eprint("[resolver] msfconsole output (tail):")
        eprint(tail)
        if proc.stderr:
            eprint("[resolver] msfconsole stderr (tail):")
            eprint("\n".join(proc.stderr.splitlines()[-30:]))
        raise RuntimeError(
            "Could not find expected JSON markers in msfconsole output; "
            "the resolver script likely failed to run inside msfconsole."
        )

    blob = stdout.split(JSON_SENTINEL_START, 1)[1].split(JSON_SENTINEL_END, 1)[0]
    return json.loads(blob.strip())


def introspect_msf_payload(module_name, payload_name, container):
    """Load one compatible payload schema after allowlist validation."""
    if not MODULE_PATH_RE.match(module_name) or not payload_name or payload_name.startswith("payload/"):
        raise ValueError("invalid module or payload identity")
    script_body = (PAYLOAD_RUBY_TEMPLATE
                   .replace("__MODULE_JSON__", json.dumps(module_name))
                   .replace("__PAYLOAD_JSON__", json.dumps(payload_name))
                   .replace("__START__", JSON_SENTINEL_START)
                   .replace("__END__", JSON_SENTINEL_END))
    ensure_container_running(container)
    msfconsole_bin = get_msfconsole_binary(container)
    try:
        written = subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-c", f"cat > {CONTAINER_SCRIPT_PATH}"],
            input=script_body, capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS)
        if written.returncode != 0:
            raise RuntimeError(f"failed to write payload introspection script: {written.stderr[:500]}")
        proc = subprocess.run(
            ["docker", "exec", "-i", container, msfconsole_bin, "-q", "-n", "-r",
             CONTAINER_SCRIPT_PATH], capture_output=True, text=True,
            timeout=MSF_TIMEOUT_SECONDS)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"payload introspection failed: {exc}") from exc
    finally:
        subprocess.run(["docker", "exec", container, "rm", "-f", CONTAINER_SCRIPT_PATH],
                       capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS)
    if proc.returncode != 0 or JSON_SENTINEL_START not in proc.stdout or JSON_SENTINEL_END not in proc.stdout:
        raise RuntimeError("Metasploit payload introspection returned no structured result")
    blob = proc.stdout.split(JSON_SENTINEL_START, 1)[1].split(JSON_SENTINEL_END, 1)[0]
    raw = json.loads(blob.strip())
    if not isinstance(raw, dict) or "error" in raw:
        raise RuntimeError(str(raw.get("error", "invalid payload introspection result")))
    from resolver_models import ModuleOption, PayloadEvidence
    options = tuple(ModuleOption(str(item["name"]),
                                 None if item.get("type") is None else str(item["type"]),
                                 bool(item.get("required", False)), item.get("default"))
                    for item in raw.get("options", ()) if isinstance(item, dict)
                    and isinstance(item.get("name"), str))
    return PayloadEvidence(payload_name, options)


# --------------------------------------------------------------------------
# Minimal dependency-free YAML emitter for this fixed schema
# --------------------------------------------------------------------------

def yaml_scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def yaml_flow_list(items):
    if not items:
        return "[]"
    return "[" + ", ".join(yaml_scalar(i) for i in items) + "]"


def emit_result_yaml(result):
    lines = []
    lines.append(f"cve_id: {yaml_scalar(result['cve_id'])}")
    lines.append(f"found: {yaml_scalar(result['found'])}")
    candidates = result["candidates"]
    if not candidates:
        lines.append("candidates: []")
        return "\n".join(lines) + "\n"

    lines.append("candidates:")
    for c in candidates:
        lines.append(f"  - module: {yaml_scalar(c['module'])}")
        lines.append(f"    rank: {yaml_scalar(c['rank'])}")
        lines.append(f"    disclosure_date: {yaml_scalar(c['disclosure_date'])}")
        lines.append(f"    platform: {yaml_flow_list(c['platform'])}")
        lines.append(f"    targets: {yaml_flow_list(c['targets'])}")
        lines.append(f"    check_supported: {yaml_scalar(c['check_supported'])}")
        lines.append(f"    references: {yaml_flow_list(c['references'])}")
        options = c["options"]
        if not options:
            lines.append("    options: []")
            continue
        lines.append("    options:")
        for opt in options:
            lines.append(f"      - name: {yaml_scalar(opt['name'])}")
            lines.append(f"        type: {yaml_scalar(opt['type'])}")
            lines.append(f"        required: {yaml_scalar(opt['required'])}")
            lines.append(f"        default: {yaml_scalar(opt['default'])}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def resolver_backend():
    """Bind the preserved MSF transport functions to the structured core."""
    return DiscoveryBackend(
        load_cache=load_json_cache,
        find_from_cache=find_candidates_from_cache,
        search_live=find_candidates_via_msfconsole_search,
        query_modules=query_msfconsole_for_modules,
        cache_description=MSF_METADATA_CACHE,
        resolve_msf_ip=resolve_msf_container_ip,
        introspect_payload=introspect_msf_payload,
    )


def resolve_msf_container_ip(container, network):
    """Return only the container IP attached to the requested Docker network."""
    ensure_container_running(container)
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f",
             "{{with index .NetworkSettings.Networks " + json.dumps(network) + "}}{{.IPAddress}}{{end}}",
             container], capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not inspect Metasploit network identity: {exc}")
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "could not inspect Metasploit network identity")
    value = proc.stdout.strip()
    return value or None


def resolve_structured(cve_id, container):
    """Public Resolver Core adapter returning a structured DiscoveryResult."""
    return discover_cve(cve_id, container, resolver_backend())


def discovery_result_to_legacy(result):
    """Adapt the structured contract to the original CLI/draft dictionary."""
    return {
        "cve_id": result.cve_id,
        "found": result.status == DiscoveryStatus.FOUND,
        "candidates": [{
            "module": candidate.module_path,
            "rank": candidate.rank,
            "disclosure_date": candidate.disclosure_date,
            "platform": list(candidate.platform),
            "targets": list(candidate.targets),
            "check_supported": candidate.check_supported,
            "references": list(candidate.references),
            "options": [option.to_dict() for option in candidate.options],
        } for candidate in result.candidates],
    }


def resolve(cve_id, container):
    """Compatibility API used by the existing CLI and draft utilities.

    New integrations should call resolve_structured().  The compatibility API
    retains the prior exception behavior for infrastructure failures.
    """
    result = resolve_structured(cve_id, container)
    if result.status == DiscoveryStatus.ENVIRONMENT_ERROR:
        raise RuntimeError("; ".join(result.errors) or "Metasploit discovery failed")
    return discovery_result_to_legacy(result)


def build_draft_from_result(cve_id, result, facts, module_path=None):
    """Pure: given an already-resolved `result` (see resolve()), mechanically
    fill one explicitly chosen module's required options from `facts` + module
    defaults. A sole candidate needs no disambiguation; multiple candidates
    require an explicit module_path and are never resolved by list order."""
    if not result["found"]:
        raise RuntimeError(f"resolver found no candidates for {cve_id}; nothing to draft.")

    candidates = result["candidates"]
    if module_path is None:
        if len(candidates) != 1:
            raise RuntimeError(
                f"resolver found {len(candidates)} candidates for {cve_id}; "
                "an explicit module selection is required"
            )
        candidate, = candidates
    else:
        candidate = next((item for item in candidates if item["module"] == module_path), None)
        if candidate is None:
            raise RuntimeError(f"selected module {module_path!r} is not a candidate for {cve_id}")
    module_fullname = candidate["module"]
    # attack/ configs store the module path without the leading type
    # segment (exploit/auxiliary/...) -- msfconsole's own shorthand once
    # the type is already implied by context.
    module_short = re.sub(r"^(exploit|auxiliary|post|payload)/", "", module_fullname)

    options_by_name = {opt["name"]: opt for opt in candidate["options"]}
    required_names = [name for name, opt in options_by_name.items() if opt["required"]]

    params = {}
    notes = {}

    for name in required_names:
        opt = options_by_name[name]
        if name in FACT_FOR_OPTION:
            params[name] = facts[FACT_FOR_OPTION[name]]
            notes[name] = f"filled from scan fact '{FACT_FOR_OPTION[name]}'"
        elif opt["default"] is not None:
            params[name] = opt["default"]
            notes[name] = "filled from module's own declared default"
        else:
            params[name] = None
            notes[name] = "required, no scan fact maps to it, no module default -- left unresolved"

    # LHOST/PAYLOAD are asked about by downstream consumers but aren't
    # required (or even present) module options at all. Handle them
    # explicitly rather than let their absence from `required_names` hide
    # them.
    if "LHOST" not in params:
        params["LHOST"] = facts.get("msf_ip")
        notes["LHOST"] = (
            "not a declared option of this module at all (payload-datastore "
            "field) -- filled from scan fact anyway, since it's "
            "facts-derivable independent of module metadata"
        )
    for name in NOT_IN_MODULE_SCHEMA:
        if name not in params:
            params[name] = None
            notes[name] = (
                "not present in the module's own option schema at all "
                "(mod.options has no PAYLOAD key -- it's populated only once "
                "a payload is selected, e.g. by msfconsole's interactive "
                "`use` auto-selection) -- left unresolved, not guessed"
            )

    return {
        "cve_id": cve_id,
        "module": module_short,
        "module_fullname": module_fullname,
        "check_supported": bool(candidate.get("check_supported", False)),
        "params": params,
        "notes": notes,
        "required_option_names": required_names,
    }


def build_draft(cve_id, container, facts):
    result = resolve(cve_id, container)
    return build_draft_from_result(cve_id, result, facts)


def classify_fields(draft):
    """Returns an ordered list of {name, value, tier, note} for every field
    a resolved attack config needs, per the 3-tier confidence system."""
    fields = [{
        "name": "module", "value": draft["module"], "tier": TIER_AUTO_VERIFIED,
        "note": "module path -- matched ground truth in all 3 live-tested CVEs",
    }]
    for name, value in draft["params"].items():
        if name in UNVERIFIED_FIELDS:
            tier = TIER_AUTO_UNVERIFIED
        elif name in STRUCTURALLY_USER_REQUIRED_FIELDS or value is None:
            tier = TIER_USER_REQUIRED
        else:
            tier = TIER_AUTO_VERIFIED
        fields.append({"name": name, "value": value, "tier": tier, "note": draft["notes"].get(name, "")})
    # LPORT was never part of draft["params"] (module metadata has no such
    # option), but a resolved, execution-ready config needs a listener port
    # for any reverse payload -- the resolver has no way to pick one
    # (arbitrary, and must avoid colliding with any other live listener).
    fields.append({
        "name": "LPORT", "value": None, "tier": TIER_USER_REQUIRED,
        "note": "arbitrary listener port -- resolver has no way to know what's already in use elsewhere",
    })
    return fields


# --------------------------------------------------------------------------
# Batch / review CLI: run the resolver across many CVEs, auto-fill what it
# can, and interactively prompt a human only for fields it genuinely can't
# determine. Layered entirely on resolve()/build_draft() above -- no new
# discovery or option-extraction logic here.
# --------------------------------------------------------------------------

PAYLOAD_LIST_RE = re.compile(r"^\s*\d+\s+(payload/\S+)")
PRIVATE_IP_RE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+$")
RECON_INTERPRETERS = ["python3", "python", "php", "perl", "bash", "ruby", "jjs", "nc", "ncat", "socat"]


def get_compatible_payloads(module_fullname, container):
    """`show payloads` for a module, parsed to a flat list of payload names
    with the leading "payload/" type segment stripped -- `set PAYLOAD ...`
    expects e.g. "cmd/unix/generic", not "payload/cmd/unix/generic" (same
    convention already applied to the module path itself). Read-only console
    introspection, same transport as the existing search fallback."""
    ensure_container_running(container)
    msfconsole_bin = get_msfconsole_binary(container)
    cmd = [
        "docker", "exec", "-i", container,
        msfconsole_bin, "-q", "-n", "-x", f"use {module_fullname}; show payloads; exit",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=MSF_TIMEOUT_SECONDS)
    except FileNotFoundError:
        raise RuntimeError("docker not found in PATH. Install Docker or ensure it's on PATH.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker exec msfconsole timed out listing payloads (container '{container}').")
    if proc.returncode != 0:
        raise RuntimeError(f"docker exec failed listing payloads (exit {proc.returncode}): {proc.stderr[:500]}")

    payloads = []
    for line in proc.stdout.splitlines():
        m = PAYLOAD_LIST_RE.match(line)
        if m:
            payloads.append(re.sub(r"^payload/", "", m.group(1)))
    return payloads


def find_container_by_ip(ip_address):
    """Best-effort: find the local Docker container whose network IP matches
    `ip_address`. This is a lab-scoped technique -- it only works because our
    targets are containers on the same Docker host we already control, NOT a
    general remote-fingerprinting method."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "-q"], capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    for cid in proc.stdout.split():
        inspect = subprocess.run(
            ["docker", "inspect", "-f",
             '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}{{.Name}}', cid],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
        parts = inspect.stdout.split()
        if not parts:
            continue
        ips, name = parts[:-1], parts[-1].lstrip("/")
        if ip_address in ips:
            return name
    return None


def attempt_interpreter_recon(rhosts_value):
    """Opt-in, best-effort: if RHOSTS looks like a private/lab IP and we can
    find the matching local container, check which interpreters it actually
    has installed via `docker exec ... which`. This is NOT a general remote
    interpreter-fingerprinting technique -- it only works in this lab
    because targets are Docker containers we already have direct exec
    access to. Returns (container_name, [found_interpreters]) or (None, [])."""
    if not rhosts_value or not PRIVATE_IP_RE.match(str(rhosts_value)):
        return None, []
    container_name = find_container_by_ip(rhosts_value)
    if not container_name:
        return None, []
    probe = " ".join(
        f"command -v {b} >/dev/null 2>&1 && echo {b};" for b in RECON_INTERPRETERS
    )
    try:
        proc = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", probe],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return container_name, []
    found = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return container_name, found


def rank_payloads(compatible_payloads, prefer_reverse, found_interpreters=None):
    """Rank compatible payloads best-first: connection-type match, then
    (if recon found interpreters) interpreter match, then meterpreter-family
    preference over a plain shell. Always applied, not just when recon runs
    -- a module can have thousands of compatible payloads (e.g. 2200+ for
    struts2_content_type_ognl), and defaulting to the alphabetically-first
    one (a `chmod` utility payload, in that module's case) is a worse
    suggestion than filtering by what the user actually asked for.

    Returns (ranked_list, recon_informed) -- recon_informed is True only when
    found_interpreters genuinely narrowed the ranking, since that's the
    specific condition that should promote PAYLOAD's confidence tier, not
    connection-type filtering alone."""
    conn_word = "reverse" if prefer_reverse else "bind"
    conn_matched = [p for p in compatible_payloads if conn_word in p]
    pool = conn_matched or compatible_payloads

    interp_matched = []
    if found_interpreters:
        interp_matched = [p for p in pool if any(f"/{i}/" in p for i in found_interpreters)]
    recon_informed = bool(interp_matched)
    ranked_pool = interp_matched or pool

    meterpreter = [p for p in ranked_pool if "meterpreter" in p]
    rest = [p for p in ranked_pool if p not in meterpreter]
    return meterpreter + rest, recon_informed


def write_yaml_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
    return path


def cmd_batch(args):
    if args.cves:
        raw_ids = [c.strip() for c in args.cves.split(",") if c.strip()]
    else:
        with open(args.cve_list) as f:
            raw_ids = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    facts = {"target_ip": args.target_ip, "target_port": args.target_port, "msf_ip": args.msf_ip}
    os.makedirs(args.out_dir, exist_ok=True)

    summary = []
    for raw in raw_ids:
        cve_id = normalize_cve(raw)
        if cve_id is None:
            eprint(f"[resolver] batch: skipping invalid CVE-ID {raw!r}")
            continue

        out_path = os.path.join(args.out_dir, f"{cve_id}.yaml")
        try:
            result = resolve(cve_id, args.msf_container)
        except RuntimeError as e:
            eprint(f"[resolver] batch: {cve_id}: {e}")
            write_yaml_file(out_path, {"cve_id": cve_id, "module_found": False, "error": str(e)})
            summary.append((cve_id, "ERROR", None, None, None))
            continue

        if not result["found"]:
            write_yaml_file(out_path, {
                "cve_id": cve_id, "module_found": False,
                "routed_to": "manual workflow (no MSF module found)",
            })
            summary.append((cve_id, "NOT FOUND -> routed to manual workflow", None, None, None))
            continue

        if len(result["candidates"]) > 1:
            write_yaml_file(out_path, {
                "cve_id": cve_id,
                "module_found": True,
                "selection_required": True,
                "candidates": result["candidates"],
                "note": "multiple candidates preserved; legacy batch mode does not select one",
            })
            summary.append((cve_id, "SELECTION REQUIRED", None, None, None))
            continue

        draft = build_draft_from_result(cve_id, result, facts)
        fields = classify_fields(draft)
        write_yaml_file(out_path, {
            "cve_id": cve_id,
            "module_found": True,
            "module": draft["module"],
            "module_fullname": draft["module_fullname"],
            "check_supported": draft["check_supported"],
            "fields": fields,
            "setup_steps_gap": (
                "no CVE-specific precondition step is visible to module metadata "
                "-- check attack/ ground truth or lab notes if one is needed"
            ),
        })
        auto = sum(1 for f in fields if f["tier"] == TIER_AUTO_VERIFIED)
        review = sum(1 for f in fields if f["tier"] == TIER_AUTO_UNVERIFIED)
        unresolved = sum(1 for f in fields if f["tier"] == TIER_USER_REQUIRED)
        summary.append((cve_id, "found", auto, review, unresolved))

    print(f"\nBatch complete -- {len(summary)} CVE(s) processed, output in {args.out_dir}/\n")
    for cve_id, status, auto, review, unresolved in summary:
        if auto is None:
            print(f"{cve_id:<16} module={status}")
        else:
            print(f"{cve_id:<16} module={status:<6} auto={auto}  needs_review={review}  unresolved={unresolved}")


class ReviewAborted(Exception):
    """Raised when stdin closes (EOF/Ctrl-D) mid-review -- distinct from a
    normal answer, so it can be handled as a clean abort rather than a
    raw traceback, without silently treating "no more input" as "accept
    defaults for everything"."""


def _prompt(prompt_text, default=None):
    try:
        raw = input(prompt_text).strip()
    except EOFError:
        raise ReviewAborted("stdin closed (EOF) while awaiting an answer")
    return raw if raw else default


def review_one_cve(entry, review_all, container):
    cve_id = entry["cve_id"]
    fields = entry["fields"]
    by_name = {f["name"]: dict(f) for f in fields}  # mutable working copy

    print(f"\n=== {cve_id} — {entry['module_fullname']} ===\n")
    for f in fields:
        shown = f["value"] if f["value"] is not None else "(not set)"
        print(f"  {f['name']:<12} {str(shown):<22} [{f['tier']}]")
    print()

    auto_fields = [f["name"] for f in fields if f["tier"] == TIER_AUTO_VERIFIED]
    if review_all and auto_fields:
        for name in auto_fields:
            cur = by_name[name]["value"]
            new = _prompt(f"  {name} [{cur}], override or Enter to accept: ", default=cur)
            by_name[name]["value"] = new
    elif auto_fields:
        accept = _prompt("Accept auto-verified fields as-is? [Y/n]: ", default="y")
        if accept.lower().startswith("n"):
            for name in auto_fields:
                cur = by_name[name]["value"]
                new = _prompt(f"  {name} [{cur}], override or Enter to accept: ", default=cur)
                by_name[name]["value"] = new

    for f in fields:
        if f["tier"] != TIER_AUTO_UNVERIFIED:
            continue
        name = f["name"]
        cur = by_name[name]["value"]
        new = _prompt(f"Confirm or override {name}: {cur} (or type new value) > ", default=cur)
        by_name[name]["value"] = new

    module_fullname = entry["module_fullname"]
    compatible_payloads = None  # fetched lazily, once, only if needed

    for f in fields:
        if f["tier"] != TIER_USER_REQUIRED or f["name"] not in ("PAYLOAD", "LPORT"):
            continue
        name = f["name"]

        if name == "LPORT":
            new = _prompt(
                "LPORT (arbitrary listener port -- avoid reusing one already active "
                "elsewhere) [suggested: 4444]: ", default="4444",
            )
            by_name["LPORT"]["value"] = int(new) if str(new).isdigit() else new
            continue

        # name == "PAYLOAD"
        conn = _prompt(
            "Connection type (bind/reverse) [default: reverse, per prior findings "
            "on this network]: ", default="reverse",
        ).lower()
        prefer_reverse = not conn.startswith("bind")

        rhosts_value = by_name.get("RHOSTS", {}).get("value")
        recon_container, found_interpreters = None, []
        if rhosts_value and PRIVATE_IP_RE.match(str(rhosts_value)):
            do_recon = _prompt(
                f"Target at {rhosts_value} looks reachable -- attempt live interpreter "
                f"recon to suggest a payload? (lab-scoped: uses direct docker exec "
                f"into the matching container, not general remote fingerprinting) [y/N]: ",
                default="n",
            ).lower()
            if do_recon.startswith("y"):
                recon_container, found_interpreters = attempt_interpreter_recon(rhosts_value)
                if recon_container:
                    print(f"  recon: found container '{recon_container}', interpreters: "
                          f"{found_interpreters or '(none found)'}")
                else:
                    print("  recon: could not match RHOSTS to a local container, skipping.")

        try:
            compatible_payloads = get_compatible_payloads(module_fullname, container)
        except RuntimeError as e:
            eprint(f"  warning: could not fetch compatible payload list: {e}")
            compatible_payloads = []

        ranked, recon_informed = rank_payloads(compatible_payloads, prefer_reverse, found_interpreters)
        if recon_informed:
            by_name["PAYLOAD"]["tier"] = TIER_AUTO_UNVERIFIED  # promoted per spec
            print(f"  recon-informed suggestion: {ranked[0]} (promoted to auto-unverified -- confirm before accepting)")

        preview = ranked[:8]
        hint = ranked[0] if ranked else None
        ranking_desc = ("reverse" if prefer_reverse else "bind") + (" + recon match" if recon_informed else "")
        print(f"  compatible payloads (showing up to 8 of {len(compatible_payloads)}, ranked for {ranking_desc}): "
              f"{', '.join(preview) if preview else '(could not fetch list)'}")
        new = _prompt(f"Payload{' [' + hint + ']' if hint else ''}: > ", default=hint)
        by_name["PAYLOAD"]["value"] = new

    return cve_id, entry["module"], entry.get("check_supported"), by_name


def write_resolved_yaml(out_dir, cve_id, module_short, check_supported, by_name):
    params = {name: f["value"] for name, f in by_name.items() if name != "module"}
    data = {
        "cve_id": cve_id,
        "module": module_short,
        "check_supported": check_supported,
        "params": params,
    }
    return write_yaml_file(os.path.join(out_dir, f"{cve_id}.yaml"), data)


def cmd_review(args):
    os.makedirs(args.out_dir, exist_ok=True)
    batch_files = sorted(glob.glob(os.path.join(args.batch, "*.yaml")))
    if not batch_files:
        eprint(f"[resolver] no batch files found in {args.batch}")
        sys.exit(1)

    completed, skipped_no_module, errored = [], [], []
    for path in batch_files:
        with open(path) as f:
            entry = yaml.safe_load(f)
        cve_id = entry["cve_id"]
        if entry.get("selection_required"):
            print(f"-- {cve_id}: multiple candidates require explicit selection -- skipping legacy review --")
            errored.append(cve_id)
            continue
        if not entry.get("module_found"):
            reason = entry.get("routed_to") or entry.get("error") or "no module found"
            print(f"-- {cve_id}: {reason} -- skipping, not part of this review flow --")
            skipped_no_module.append(cve_id)
            continue
        try:
            cve_id, module_short, check_supported, by_name = review_one_cve(
                entry, args.review_all, args.msf_container
            )
        except ReviewAborted as e:
            eprint(f"\n[resolver] review aborted ({e}) -- stopping before {cve_id}.")
            remaining = [yaml.safe_load(open(p))["cve_id"] for p in batch_files[batch_files.index(path):]]
            errored.extend(remaining)
            break
        out_path = write_resolved_yaml(
            args.out_dir, cve_id, module_short, check_supported, by_name
        )
        print(f"-> wrote {out_path}")
        completed.append(cve_id)

    print(f"\n=== Review complete ===")
    print(f"resolved & ready: {len(completed)}  {completed}")
    print(f"routed to manual workflow (no module): {len(skipped_no_module)}  {skipped_no_module}")
    if errored:
        print(f"not reviewed (aborted before reaching them): {len(errored)}  {errored}")
    return 1 if errored else 0


def main():
    parser = argparse.ArgumentParser(prog="resolver.py")
    sub = parser.add_subparsers(dest="command", required=True)
    run_p = sub.add_parser("run", help="Resolve MSF module candidates for a CVE-ID")
    run_p.add_argument("--cve", required=True, help="CVE-ID, e.g. CVE-2017-5638")
    run_p.add_argument(
        "--msf-container", default=DEFAULT_MSF_CONTAINER,
        help=f"Name of the running Metasploit Docker container (default: {DEFAULT_MSF_CONTAINER}, "
             f"override via MSF_RESOLVER_CONTAINER env var or this flag)",
    )

    batch_p = sub.add_parser("batch", help="Batch-resolve multiple CVEs into confidence-tiered draft configs")
    batch_src = batch_p.add_mutually_exclusive_group(required=True)
    batch_src.add_argument("--cves", help="Comma-separated CVE-IDs")
    batch_src.add_argument("--cve-list", help="Path to a file with one CVE-ID per line")
    batch_p.add_argument("--out-dir", default="resolver_output/batch")
    batch_p.add_argument("--target-ip", default=DEFAULT_FACTS["target_ip"])
    batch_p.add_argument("--target-port", type=int, default=DEFAULT_FACTS["target_port"])
    batch_p.add_argument("--msf-ip", default=DEFAULT_FACTS["msf_ip"])
    batch_p.add_argument("--msf-container", default=DEFAULT_MSF_CONTAINER)

    review_p = sub.add_parser("review", help="Interactively review a batch and produce resolved configs")
    review_p.add_argument("--batch", required=True, help="Path to the batch output directory")
    review_p.add_argument("--out-dir", default="resolver_output/resolved")
    review_p.add_argument("--review-all", action="store_true", help="Also prompt for auto-verified fields")
    review_p.add_argument("--msf-container", default=DEFAULT_MSF_CONTAINER)

    args = parser.parse_args()

    if args.command == "batch":
        cmd_batch(args)
        sys.exit(0)

    if args.command == "review":
        sys.exit(cmd_review(args))

    cve_id = normalize_cve(args.cve)
    if cve_id is None:
        eprint(f"[resolver] invalid CVE-ID format: {args.cve!r} (expected CVE-YYYY-NNNN...)")
        sys.exit(2)

    try:
        result = resolve(cve_id, args.msf_container)
    except RuntimeError as e:
        eprint(f"[resolver] error: {e}")
        sys.exit(1)

    sys.stdout.write(emit_result_yaml(result))
    sys.exit(0)


if __name__ == "__main__":
    main()
