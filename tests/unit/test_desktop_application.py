from __future__ import annotations

from kalama.desktop.application import MockDesktopApplication
from kalama.desktop.contracts import FormContext
from kalama.desktop.ui import DesktopBridge


def _attack_context() -> dict[str, object]:
    return {"run_id": "DEMO1", "kind": "attack", "item_id": "CVE-2015-1427",
            "phase": "before", "revision": 1}


def test_mock_attack_and_patch_are_identity_scoped() -> None:
    service = MockDesktopApplication()
    attack = service.get_form(FormContext(**_attack_context()))
    patch = service.get_form(FormContext("DEMO1", "patch", "patch-001", "patch", 1))
    assert attack.context.item_id == "CVE-2015-1427"
    assert patch.context.item_id == "patch-001"
    assert "CVE-2015-1427" in attack.data["cves"]
    assert "patch-001" in patch.data["actions"]


def test_yaml_apply_rejects_a_stale_revision_without_mutating_draft() -> None:
    bridge = DesktopBridge(MockDesktopApplication())
    loaded = bridge.get_form(_attack_context())
    assert loaded["ok"]
    raw = loaded["data"]
    raw["data"]["revision"] = 2
    saved = bridge.save_form(raw)
    assert not saved["ok"]
    assert saved["error"]["code"] == "STALE_FORM"


def test_yaml_round_trip_preserves_boolean_and_multiline_command() -> None:
    bridge = DesktopBridge(MockDesktopApplication())
    loaded = bridge.get_form(_attack_context())
    document = loaded["data"]
    document["data"]["cves"]["CVE-2015-1427"]["module_options"]["SSL"]["confirmed"] = False
    document["data"]["cves"]["CVE-2015-1427"]["pre_attack"]["command"] = "echo one\necho two\n"
    dumped = bridge.dump_yaml({"data": document["data"]})
    assert dumped["ok"]
    applied = bridge.apply_yaml({**document, "yaml": dumped["data"]})
    assert applied["ok"]
    restored = applied["data"]["data"]["cves"]["CVE-2015-1427"]
    assert restored["module_options"]["SSL"]["confirmed"] is False
    assert restored["pre_attack"]["command"] == "echo one\necho two\n"
