"""Pure evidence-driven patch planning."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Protocol, Sequence

from .models import (
    FixType, PatchAction, PatchPlan, PatchStrategy, PlanningReason, PlanningStatus,
    RemediationCandidate,
)


class RemediationProvider(Protocol):
    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]],
                  target_facts: Mapping[str, Any] | None = None
                  ) -> RemediationCandidate | None: ...


def _package_key(occurrence: Mapping[str, Any]) -> str | None:
    return occurrence.get("package_purl") or occurrence.get("package_name")


def _evidence_fix_type(occurrences: Sequence[Mapping[str, Any]]) -> FixType | None:
    classes = {x.get("result_class") for x in occurrences}
    ecosystems = {str(x.get("result_type") or "").lower() for x in occurrences}
    if "os-pkgs" in classes or ecosystems & {"debian", "ubuntu", "alpine", "rpm", "rhel", "centos"}:
        return FixType.C
    return None


def build_patch_plan(run_id: str, successful_cves: Sequence[tuple[int, str]],
                     all_ranked: Sequence[Mapping[str, Any]],
                     provider: RemediationProvider,
                     target_facts: Mapping[str, Any] | None = None) -> PatchPlan:
    occurrences_by_cve = {str(x.get("cve_id")): list(x.get("occurrences") or ()) for x in all_ranked}
    target_ids = {cve for _, cve in successful_cves}
    package_to_all_cves: dict[str, set[str]] = defaultdict(set)
    for cve_id, occurrences in occurrences_by_cve.items():
        for occurrence in occurrences:
            if isinstance(occurrence, Mapping) and (key := _package_key(occurrence)):
                package_to_all_cves[str(key)].add(cve_id)
    grouped: dict[str, dict[str, Any]] = {}
    unresolved = []
    for rank, cve_id in sorted(successful_cves):
        occurrences = [x for x in occurrences_by_cve.get(cve_id, ()) if isinstance(x, Mapping)]
        if not occurrences:
            unresolved.append((rank, cve_id))
            continue
        for occurrence in occurrences:
            key = _package_key(occurrence)
            if not key:
                unresolved.append((rank, cve_id))
                continue
            item = grouped.setdefault(str(key), {"rank": rank, "cves": set(), "occurrences": []})
            item["rank"] = min(item["rank"], rank)
            item["cves"].add(cve_id)
            item["occurrences"].append(dict(occurrence))

    provisional = []
    for key, item in grouped.items():
        occurrences = item["occurrences"]
        package_name = next((x.get("package_name") for x in occurrences if x.get("package_name")), None)
        ecosystem = next((x.get("result_type") for x in occurrences if x.get("result_type")), None)
        installed = tuple(sorted({x.get("installed_version") for x in occurrences
                                  if x.get("installed_version")}))
        fixed = tuple(sorted({v for x in occurrences for v in (x.get("fixed_versions") or ())
                              if isinstance(v, str)}))
        candidate = provider.candidate(package_name=package_name or key, ecosystem=ecosystem,
                                       installed_versions=installed, scanner_fixed_versions=fixed,
                                       occurrences=occurrences, target_facts=target_facts)
        fix_type = candidate.fix_type if candidate and candidate.fix_type else _evidence_fix_type(occurrences)
        strategy = candidate.strategy if candidate else None
        reasons = []
        if fix_type is None: reasons.append(PlanningReason.FIX_TYPE_UNRESOLVED)
        if candidate is None or not candidate.target_version:
            reasons.append(PlanningReason.TARGET_VERSION_UNRESOLVED)
        if candidate is None or not candidate.trusted or not candidate.source_authority:
            reasons.append(PlanningReason.ARTIFACT_SOURCE_UNRESOLVED)
        if strategy is None: reasons.append(PlanningReason.PATCH_STRATEGY_UNRESOLVED)
        if candidate and candidate.same_branch is None:
            reasons.append(PlanningReason.BRANCH_SEMANTICS_UNRESOLVED)
        if candidate and candidate.fallback_used and candidate.same_branch is False:
            before_major = {x.split(".", 1)[0] for x in installed if x[:1].isdigit()}
            after_major = candidate.target_version.split(".", 1)[0] if candidate.target_version else None
            if before_major and after_major not in before_major:
                reasons.append(PlanningReason.MAJOR_VERSION_CONFIRMATION_REQUIRED)
        if candidate and candidate.eol and not candidate.target_version:
            reasons.append(PlanningReason.EOL_DATA_LIMITATION)
        if fix_type == FixType.A and candidate and (not candidate.build_system
                                                     or not candidate.source_identifier):
            reasons.append(PlanningReason.BUILD_PLAN_REQUIRES_HUMAN_INPUT)
        reasons = tuple(sorted(set(reasons), key=lambda x: x.value))
        status = (PlanningStatus.WAITING_FOR_USER_INPUT if reasons
                  else PlanningStatus.READY_FOR_PATCH_EXECUTION)
        provisional.append((item["rank"], key, item, PatchAction(
            "", tuple(sorted(item["cves"])),
            tuple(sorted(package_to_all_cves[key] - target_ids)), key, package_name, ecosystem,
            tuple(sorted(occurrences, key=lambda x: repr(sorted(x.items())))), installed, fixed,
            fix_type, strategy, candidate, status, reasons)))
    for rank, cve_id in unresolved:
        key = f"unresolved:{cve_id}"
        provisional.append((rank, key, None, PatchAction(
            "", (cve_id,), (), key, None, None, (), (), (), None, None, None,
            PlanningStatus.WAITING_FOR_USER_INPUT,
            (PlanningReason.PACKAGE_MAPPING_UNRESOLVED,))))
    provisional.sort(key=lambda x: (x[0], x[1]))
    # replace action IDs without mutating the frozen action records.
    from dataclasses import replace
    actions = tuple(replace(item[3], action_id=f"patch-{index:03d}")
                    for index, item in enumerate(provisional, 1))
    readiness = (PlanningStatus.WAITING_FOR_USER_INPUT
                 if any(x.status == PlanningStatus.WAITING_FOR_USER_INPUT for x in actions)
                 else PlanningStatus.READY_FOR_PATCH_EXECUTION)
    return PatchPlan(run_id, actions, readiness)
