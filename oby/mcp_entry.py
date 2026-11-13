"""Run invisible-playwright-mcp on this process's stdio.

The parent (`oby mcp`) has already started the recorder and put its address
in the environment. stdout is the MCP protocol, so this module prints nothing.
"""

from __future__ import annotations


def main() -> None:
    from oby.trust import accept_recorder_certificate

    accept_recorder_certificate()
    from invisible_playwright_mcp.mcp import server as mcp_server

    from oby.mcp import teach

    teach(mcp_server)
    from invisible_playwright_mcp.cli import main as serve

    serve()


if __name__ == "__main__":
    main()
