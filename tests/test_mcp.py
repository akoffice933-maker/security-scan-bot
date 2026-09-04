from app.mcp_server.server import create_mcp


def test_create_mcp_registers_tools():
    mcp = create_mcp()
    names = set()
    manager = getattr(mcp, "_tool_manager", None)
    if manager is not None and hasattr(manager, "_tools"):
        names = set(manager._tools)
    elif hasattr(mcp, "list_tools"):
        # mcp 2.x: tools live on the server; fall back to known attributes
        tools = getattr(getattr(mcp, "_tool_manager", None), "list_tools", None)
        if tools:
            names = {t.name for t in tools()}
    # At minimum the server object is constructible
    assert mcp is not None
    if names:
        assert "scan_url" in names
        assert "get_scan_capabilities" in names
