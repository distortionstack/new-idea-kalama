"""Production dependency composition and one-boundary stage dispatch."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Mapping, Sequence, Any

from resolver import resolver_backend

from .dispatcher import dispatch_stage
from .infrastructure import WORKBENCH_NAME
from .evaluation import EvaluationOrchestrator
from .execution import (
    BeforeExploitOrchestrator,
    DockerEnvironmentValidator,
    DockerLabCommandExecutor,
    DockerMetasploitExecutor,
)
from .orchestrator import PrioritizationOrchestrator, production_step3_executor
from .prioritizer import CISAKEVProvider, FIRSTEPSSProvider
from .reexploit import ReexploitOrchestrator
from .remediation import (
    DockerPatchBackend,
    PatchConfirmationOrchestrator,
    PatchExecutionOrchestrator,
    PatchPlanningOrchestrator,
    PatchRetryOrchestrator,
)
from .remediation.discovery import AutomaticRemediationProvider, RemediationDiscoveryService
from .resolution import AttackFormOrchestrator, ResolverOrchestrator, production_step4_processor
from .guidance import GuidanceService, OllamaConfig, OllamaProvider
from .state import RunState, RunStatus, StateStore
from .target import SubprocessCommandRunner, WorkbenchToolRunner, execute_step2
from .verification import AfterScanOrchestrator, docker_image_inspector, production_after_scanner


class ManualRemediationProvider:
    """Honest production fallback when no remediation discovery adapter exists.

    Returning no candidate makes the existing planner emit a canonical Patch
    Form. It never guesses a version, source, or patch strategy.
    """

    def candidate(self, *, package_name: str, ecosystem: str | None,
                  installed_versions: Sequence[str], scanner_fixed_versions: Sequence[str],
                  occurrences: Sequence[Mapping[str, Any]]):
        return None


class ProductionRuntime:
    def __init__(self, output_root: Path):
        self.store = StateStore(output_root)
        self.runner = SubprocessCommandRunner()
        self.scanner_runner = WorkbenchToolRunner(self.runner)

    def start(self, image: str) -> RunState:
        initial = PrioritizationOrchestrator(
            self.store,
            lambda request: execute_step2(request, self.scanner_runner),
            production_step3_executor(
                epss_provider=FIRSTEPSSProvider(), kev_provider=CISAKEVProvider()),
        )
        state = initial.run(image)
        return self.store.load(state.run_id)

    def submit_attack_form(self, run_id: str, path: Path) -> RunState:
        backend = resolver_backend()
        loader = (None if backend.introspect_payload is None else
                  lambda module, payload: backend.introspect_payload(
                      module, payload, "msf-resolver-host"))
        AttackFormOrchestrator(
            self.store, payload_introspector=loader).apply_attack_form(run_id, path)
        return self.store.load(run_id)

    def submit_patch_form(self, run_id: str, path: Path) -> RunState:
        PatchConfirmationOrchestrator(self.store).apply_patch_form(run_id, path)
        return self.store.load(run_id)

    def retry_patch_execution(self, run_id: str, *, edit_plan: bool) -> RunState:
        PatchRetryOrchestrator(self.store).retry(run_id, edit_plan=edit_plan)
        return self.store.load(run_id)

    def continue_once(self, run_id: str) -> RunState:
        state = self.store.load(run_id)
        if state.status != RunStatus.PAUSED:
            return state
        selected = dispatch_stage(state)
        targets = {
            "victim": f"victim-{run_id}",
            "victim-after": f"victim-after-{run_id}",
            # Preserve the artifact-level logical target while routing it to
            # the current managed container, never the legacy container.
            "kalama-workbench": WORKBENCH_NAME,
            "msf-resolver-host": "msf-resolver-host",
        }
        common = (
            DockerEnvironmentValidator(self.runner),
            DockerMetasploitExecutor(self.runner),
        )
        stages = {
            "resolver": lambda: ResolverOrchestrator(
                self.store,
                production_step4_processor(resolver_backend(), msf_container="msf-resolver-host"),
                guidance_service=self._guidance_service(),
            ).run(run_id),
            "before_exploit": lambda: BeforeExploitOrchestrator(
                self.store, common[0], common[1], DockerLabCommandExecutor(self.runner, targets),
            ).run(run_id),
            "patch_plan": lambda: self._patch_plan_provider(state).run(run_id),
            "patch_execution": lambda: PatchExecutionOrchestrator(
                self.store, DockerPatchBackend(self.runner)).run(run_id),
            "after_scan": lambda: AfterScanOrchestrator(
                self.store, production_after_scanner(self.scanner_runner),
                docker_image_inspector(self.runner),
            ).run(run_id),
            "reexploit": lambda: ReexploitOrchestrator(
                self.store, common[0], common[1], DockerLabCommandExecutor(self.runner, targets),
            ).run(run_id),
            "evaluation": lambda: EvaluationOrchestrator(self.store).run(run_id),
        }
        stages[selected]()  # Exactly one stage invocation; intentionally no loop.
        return self.store.load(run_id)

    def _patch_plan_provider(self, state: RunState) -> PatchPlanningOrchestrator:
        """Build a discovery-backed planning orchestrator wired to current target facts."""
        facts = state.target.facts if state.target else None
        container_name = None
        if isinstance(facts, Mapping):
            container_name = facts.get("container_name")
        source_root = os.environ.get("KALAMA_SOURCE_ROOT", "").strip() or None
        service = RemediationDiscoveryService(
            runner=self.runner, container_name=container_name, source_root=source_root)
        provider = AutomaticRemediationProvider(
            service, output_root=self.store.output_root, container_name=container_name,
            source_root=source_root)
        return PatchPlanningOrchestrator(self.store, provider)

    @staticmethod
    def _guidance_service() -> GuidanceService | None:
        enabled = os.environ.get("KALAMA_GUIDANCE_ENABLED", "").strip().casefold()
        if enabled not in {"1", "true", "yes", "on"}:
            return None
        config = OllamaConfig(
            base_url=os.environ.get("KALAMA_OLLAMA_URL", "http://127.0.0.1:11434"),
            model=os.environ.get("KALAMA_OLLAMA_MODEL", "llama3.2:3b"),
            timeout=float(os.environ.get("KALAMA_OLLAMA_TIMEOUT", "45")))
        selected = os.environ.get("KALAMA_GUIDANCE_CVES", "").strip()
        cve_ids = (frozenset(x.strip().upper() for x in selected.split(",") if x.strip())
                   if selected else None)
        return GuidanceService(OllamaProvider(config), cve_ids=cve_ids)


def build_runtime(output_root: Path | str = Path("output")) -> ProductionRuntime:
    return ProductionRuntime(Path(output_root))
