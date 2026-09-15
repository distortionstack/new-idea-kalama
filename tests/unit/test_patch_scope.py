import unittest

from kalama.remediation.codec import validate_patch_plan
from kalama.remediation.confirmation import PatchSubmissionError, apply_patch_confirmations
from kalama.remediation.models import (ActionDisposition, FixType, PatchAction, PatchPlan,
                                      PatchStrategy, PlanningStatus, RemediationCandidate)


def action(action_id, *, disposition=ActionDisposition.EXECUTE, reason=None, rebuild=False):
    candidate = RemediationCandidate(
        target_version="2.3.32", trusted=True, source_authority="human",
        source_identifier="apache:2.3.32", build_system="maven",
        replacement_target="example:patched", checksum="sha256:abc")
    return PatchAction(action_id, ("CVE-2099-0001",), (), "pkg:maven/x@y", "x", "jar",
                       ({"installed_version": "y"},), ("y",), ("z",), FixType.A,
                       PatchStrategy.REBUILD if rebuild else PatchStrategy.PACKAGE_MANAGER,
                       candidate, PlanningStatus.WAITING_FOR_USER_INPUT, (),
                       {"command": "build", "validation_command": "verify"}, (), disposition, reason)


class PatchScopeTests(unittest.TestCase):
    def test_one_execute_and_six_scoped_skips_are_ready(self):
        actions = [action("patch-004", rebuild=True)] + [
            action(f"patch-{i:03d}", disposition=ActionDisposition.SKIP_OUT_OF_SCOPE,
                   reason="no attributable exploit evidence") for i in (1, 2, 3, 5, 6, 7)]
        plan = validate_patch_plan(PatchPlan("run", tuple(actions), PlanningStatus.WAITING_FOR_USER_INPUT))
        self.assertEqual(plan.readiness, PlanningStatus.READY_FOR_PATCH_EXECUTION)
        self.assertEqual(plan.actions[1].status, PlanningStatus.SKIP_OUT_OF_SCOPE)
        self.assertEqual(plan.actions[1].to_dict()["disposition_reason"], "no attributable exploit evidence")

    def test_skip_requires_reason(self):
        with self.assertRaisesRegex(ValueError, "disposition_reason"):
            validate_patch_plan(PatchPlan("run", (action("x", disposition=ActionDisposition.SKIP_OUT_OF_SCOPE),), PlanningStatus.WAITING_FOR_USER_INPUT))

    def test_rebuild_requires_all_provenance(self):
        incomplete = action("x", rebuild=True)
        incomplete = PatchAction(**{**incomplete.__dict__, "candidate": RemediationCandidate(target_version="2.3.32", trusted=True, source_authority="human")})
        plan = validate_patch_plan(PatchPlan("run", (incomplete,), PlanningStatus.WAITING_FOR_USER_INPUT))
        self.assertEqual(plan.actions[0].status, PlanningStatus.WAITING_FOR_USER_INPUT)

    def test_legacy_action_defaults_to_execute(self):
        raw = action("x").to_dict(); raw.pop("disposition"); raw.pop("disposition_reason")
        from kalama.remediation.codec import action_from_dict
        self.assertEqual(action_from_dict(raw).disposition, ActionDisposition.EXECUTE)

    def test_source_built_artifact_can_use_image_replacement(self):
        item = action("x", rebuild=True)
        item = PatchAction(**{**item.__dict__, "strategy": PatchStrategy.IMAGE_REPLACEMENT})
        plan = validate_patch_plan(PatchPlan("run", (item,), PlanningStatus.WAITING_FOR_USER_INPUT))
        self.assertEqual(plan.actions[0].status, PlanningStatus.READY_FOR_PATCH_EXECUTION)
        self.assertEqual(plan.actions[0].candidate.build_system, "maven")
        self.assertEqual(plan.actions[0].candidate.replacement_target, "example:patched")

    def test_image_replacement_requires_immutable_identity(self):
        item = action("x", rebuild=True)
        candidate = RemediationCandidate(target_version="2.3.32", trusted=True,
                                         source_authority="human", source_identifier="apache",
                                         build_system="maven", replacement_target="example:patched")
        item = PatchAction(**{**item.__dict__, "strategy": PatchStrategy.IMAGE_REPLACEMENT,
                              "candidate": candidate})
        plan = validate_patch_plan(PatchPlan("run", (item,), PlanningStatus.WAITING_FOR_USER_INPUT))
        self.assertEqual(plan.actions[0].status, PlanningStatus.WAITING_FOR_USER_INPUT)
