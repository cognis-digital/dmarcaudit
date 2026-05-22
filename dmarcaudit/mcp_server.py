"""DMARCAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from dmarcaudit.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-dmarcaudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-dmarcaudit[mcp]'")
        return 1
    app = FastMCP("dmarcaudit")

    @app.tool()
    def dmarcaudit_scan(target: str) -> str:
        """Grade SPF/DKIM/DMARC posture & spoofability from DNS records. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
