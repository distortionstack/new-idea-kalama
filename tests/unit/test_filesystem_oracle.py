from types import SimpleNamespace

from kalama.execution.attempt import _filesystem_impact, _filesystem_probe
from kalama.execution.models import ImpactEvidenceStatus, OperationState


def plan(command):
    return SimpleNamespace(payload_options=(("CMD", command),))


def test_touch_command_declares_generic_filesystem_probe():
    assert _filesystem_probe(plan("touch /tmp/pwned")) == "/tmp/pwned"


def test_new_marker_is_positive_impact():
    result = _filesystem_impact(
        before=(OperationState.EXECUTED, "ABSENT"),
        after=(OperationState.EXECUTED, "1700000000:0:42"),
        path="/tmp/pwned",
    )
    assert result.status == ImpactEvidenceStatus.COLLECTED
    assert result.confirmed is True
    assert result.basis == "FILESYSTEM_MARKER_CHANGED"


def test_unchanged_existing_marker_is_negative_not_positive():
    result = _filesystem_impact(
        before=(OperationState.EXECUTED, "1700000000:0:42"),
        after=(OperationState.EXECUTED, "1700000000:0:42"),
        path="/tmp/pwned",
    )
    assert result.complete_negative is True
    assert result.confirmed is False


def test_changed_existing_marker_is_positive_and_not_stale():
    result = _filesystem_impact(
        before=(OperationState.EXECUTED, "1700000000:0:42"),
        after=(OperationState.EXECUTED, "1700000001:0:42"),
        path="/tmp/pwned",
    )
    assert result.confirmed is True


def test_unavailable_probe_is_inconclusive():
    result = _filesystem_impact(
        before=(OperationState.EXECUTED, "ABSENT"),
        after=(OperationState.EXECUTION_ERROR, ""),
        path="/tmp/pwned",
    )
    assert result.status == ImpactEvidenceStatus.UNKNOWN
    assert result.confirmed is False
