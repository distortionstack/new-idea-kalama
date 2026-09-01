"""Canonical RunState-to-stage selection; contains no stage business logic."""

from .state import PipelineStage, RunState, StageStatus


class DispatchError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def dispatch_stage(state: RunState) -> str:
    stage = state.current_stage
    if stage == PipelineStage.STEP_4_RESOLVER:
        resolver = state.stage(PipelineStage.STEP_4_RESOLVER).status
        before = state.stage(PipelineStage.STEP_4_BEFORE_EXPLOIT).status
        if resolver == StageStatus.NOT_STARTED:
            return "resolver"
        if resolver == StageStatus.SUCCEEDED and before == StageStatus.NOT_STARTED:
            return "before_exploit"
    if stage == PipelineStage.STEP_4_BEFORE_EXPLOIT:
        return "before_exploit"
    if stage in (PipelineStage.STEP_5_PATCH, PipelineStage.STEP_5_PATCH_PLAN):
        return "patch_plan"
    if stage == PipelineStage.STEP_5_PATCH_EXECUTION:
        return "patch_execution"
    if stage == PipelineStage.STEP_6_AFTER_SCAN:
        return "after_scan"
    if stage == PipelineStage.STEP_7_REEXPLOIT:
        return "reexploit"
    if stage == PipelineStage.STEP_8_EVALUATION:
        return "evaluation"
    raise DispatchError("NO_EXECUTABLE_STAGE", f"no executable stage at {stage.value if stage else 'none'}")
