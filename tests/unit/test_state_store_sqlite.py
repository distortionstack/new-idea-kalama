from datetime import datetime, timezone

from kalama.state import RunStatus, StateStore


def test_run_state_is_indexed_in_local_sqlite_and_discovered(tmp_path):
    store = StateStore(tmp_path / "output")
    state = store.create("example:latest", now=datetime(2026, 1, 1, tzinfo=timezone.utc),
                         run_id_generator=lambda: "Ab123")

    assert store.database_path.exists()
    assert store.discover()[0].run_id == state.run_id
    assert store.discover()[0].status == RunStatus.INITIALIZING


def test_existing_json_states_are_migrated_to_sqlite(tmp_path):
    output = tmp_path / "output"
    legacy = StateStore(output)
    state = legacy.create("example:legacy", now=datetime(2026, 1, 1, tzinfo=timezone.utc),
                          run_id_generator=lambda: "Lg123")
    legacy.database_path.unlink()
    migrated = StateStore(output)
    assert migrated.discover()[0].run_id == state.run_id
