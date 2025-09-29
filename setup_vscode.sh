#!/bin/bash

CONFIG_FILE="$HOME/.config/Code/User/globalStorage/github.copilot-chat/mcpServers.json"

mkdir -p "$(dirname "$CONFIG_FILE")"

cat > "$CONFIG_FILE" << 'EOF'
{
  "mcpServers": {
    "ida": {
      "command": "python3",
      "args": ["/home/y/WORK/h1/r3/mcp_ida/ida_mcp_server.py"],
      "env": {}
    }
  }
}
EOF

echo "MCP server configuration updated to: $CONFIG_FILE"
echo ""
echo "Restart VS Code completely and try:"
echo "   @ida ida_get_functions"
echo "   @ida ida_get_function_info address=0x401000"
