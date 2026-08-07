import manager.manager.api.raw as raw_mod

def test_raw_module_uses_shared_resolver_not_local_map():
    # The local _TIME_WINDOWS map must be gone; the shared resolver is the source of truth.
    assert not hasattr(raw_mod, "_TIME_WINDOWS")

def test_raw_resolve_delegates(monkeypatch):
    from manager.manager.timewindow import resolve_window
    # 30s was not in the old _TIME_WINDOWS map; shared vocab now supports it
    s, e = resolve_window("30s", now=1000)
    assert (s, e) == (970, 1000)
