"""Production dependency composition and one-boundary stage dispatch."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Mapping, Sequence, Any

from kalama.metasploit_fixtures import registry_from_env
from kalama.resolver.backend import resolver_backend

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
from .reexploit.orchestrator import ReexploitRetryOrchestrator
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
from .config import load_config, load_evidence_config
from .knowledge import KnowledgeStore
from .knowledge.lab_notes import import_repository_lab_notes
from .remediation.knowledge import KnowledgeRemediationProvider
from .state import RunState, RunStatus, StateStore
from .target import SubprocessCommandRunner, WorkbenchToolRunner, execute_step2
from .verification import (
    AfterScanOrchestrator, AfterScanRetryOrchestrator, docker_after_target_inspector,
    docker_image_inspector, production_after_scanner,
)


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

    def start(self, image: str, *, dynamic_scan: str = "off",
              nuclei_profile: str = "safe-cve-http",
              dynamic_scan_required: bool = False) -> RunState:
        import_repository_lab_notes(KnowledgeStore(self.store.output_root))
        initial = PrioritizationOrchestrator(
            self.store,
            lambda request: execute_step2(request, self.scanner_runner),
            production_step3_executor(
                epss_provider=FIRSTEPSSProvider(), kev_provider=CISAKEVProvider()),
        )
        state = initial.run(image)
        state = self.store.load(state.run_id)
        # Shadow dynamic probing runs after Step 3 on the committed Top-N
        # candidates. Feature off (default) returns the v1 state untouched.
        if dynamic_scan == "nuclei" and state.status == RunStatus.PAUSED:
            from .dynamic_shadow import DynamicShadowOrchestrator, dynamic_config_from_env
            config = dynamic_config_from_env(
                dynamic_scan=dynamic_scan, nuclei_profile=nuclei_profile,
                required=dynamic_scan_required)
            state = DynamicShadowOrchestrator(
                self.store, command_runner=self.runner).run_shadow(state.run_id, config)
        elif dynamic_scan not in ("off", "nuclei"):
            raise ValueError(
                f"DYNAMIC_CONFIG_INVALID: --dynamic-scan must be off|nuclei, got {dynamic_scan!r}")
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

    def retry_patch_execution(self, run_id: str, *, edit_plan: bool = False,
                              force_smoke_failed: bool = False) -> RunState:
        state = self.store.load(run_id)
        if (state.status == RunStatus.FAILED_FATAL
                and getattr(state.current_stage, "value", None) == "STEP_6_AFTER_SCAN"):
            if edit_plan or force_smoke_failed:
                raise ValueError("AFTER_SCAN_RETRY_REQUIRES_SAME_PLAN: use --same-plan")
            AfterScanRetryOrchestrator(
                self.store, docker_after_target_inspector(self.runner)).retry(run_id)
        elif (state.status == RunStatus.FAILED_FATAL
                and getattr(state.current_stage, "value", None) == "STEP_7_REEXPLOIT"):
            if edit_plan or force_smoke_failed:
                raise ValueError("REEXPLOIT_RETRY_DOES_NOT_ACCEPT_PLAN_FLAGS")
            ReexploitRetryOrchestrator(self.store).retry(run_id)
        else:
            PatchRetryOrchestrator(self.store).retry(
                run_id, edit_plan=edit_plan, force_smoke_failed=force_smoke_failed)
        return self.store.load(run_id)

    def continue_once(self, run_id: str, *, resolver_cve: str | None = None) -> RunState:
        import_repository_lab_notes(KnowledgeStore(self.store.output_root))
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
        fixture_registry = registry_from_env()
        common = (
            DockerEnvironmentValidator(self.runner),
            DockerMetasploitExecutor(self.runner, fixture_registry=fixture_registry),
        )
        stages = {
            "resolver": lambda: ResolverOrchestrator(
                self.store,
                production_step4_processor(resolver_backend(), msf_container="msf-resolver-host"),
                resolver_scope=(resolver_cve,),
                guidance_service=self._guidance_service(),
                knowledge_store=KnowledgeStore(self.store.output_root),
                evidence_collector_factory=self._evidence_collector_factory(),
                evidence_config=load_evidence_config(),
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
        return PatchPlanningOrchestrator(self.store, KnowledgeRemediationProvider(
            provider, KnowledgeStore(self.store.output_root)))

    @staticmethod
    def _guidance_service() -> GuidanceService | None:
        config = load_config()
        if not config.enabled:
            return None
        # A bad optional LLM configuration degrades to the existing review
        # workflow; it must never make a normal run unusable.
        if config.error() is not None or config.provider != "ollama":
            return None
        provider_config = OllamaConfig(base_url=config.base_url, model=config.model,
                                       timeout=float(os.environ.get("KALAMA_OLLAMA_TIMEOUT", "45")))
        selected = os.environ.get("KALAMA_GUIDANCE_CVES", "").strip()
        cve_ids = (frozenset(x.strip().upper() for x in selected.split(",") if x.strip())
                   if selected else None)
        return GuidanceService(OllamaProvider(provider_config), cve_ids=cve_ids)

    def _evidence_collector_factory(self):
        """Factory building the Task 2/3 EvidenceCollector post-analysis.

        The orchestrator supplies target facts, occurrences and selected MSF
        candidates once analysis exists; this factory only binds the shared
        production inputs (knowledge store, output root, source switches).
        """
        from .resolution.llm_fields import build_production_collector

        knowledge_store = KnowledgeStore(self.store.output_root)
        output_root = self.store.output_root
        evidence_config = load_evidence_config()
        bound_store = knowledge_store

        def factory(*, knowledge_store=None, target_facts=None,
                    occurrences=(), candidates_by_cve=None, **_ignored):
            return build_production_collector(
                knowledge_store=knowledge_store if knowledge_store is not None else bound_store,
                target_facts=target_facts,
                occurrences=occurrences,
                candidates_by_cve=candidates_by_cve,
                output_root=output_root,
                evidence_config=evidence_config,
            )

        return factory


def build_runtime(output_root: Path | str = Path("output")) -> ProductionRuntime:
    return ProductionRuntime(Path(output_root))
