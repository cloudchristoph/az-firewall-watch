"""``python -m mcp_server``: run the MCP server."""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
