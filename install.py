#!/usr/bin/env python3

import os
import shutil
import sys
import json
import argparse

def setup_vscode_config(server_path):
    config_file = os.path.expanduser("~/.config/Code/User/mcp.json")
    
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    
    config = {
        "mcpServers": {
            "ida": {
                "command": "python3",
                "args": [server_path],
                "env": {}
            }
        }
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"MCP server configuration updated to: {config_file}")
        print("Restart VS Code completely and try:")
        print("   @ida ida_get_functions")
        print("   @ida ida_get_function_info address=0x401000")
        return True
    except Exception as e:
        print(f"Failed to write VS Code config: {e}")
        return False

def install_plugin():
    plugin_file = "ida_mcp_plugin.py"
    
    if not os.path.exists(plugin_file):
        print(f"Error: {plugin_file} not found")
        return False
    
    ida_plugins_dirs = [
        os.path.expanduser("~/.idapro/plugins"),
        os.path.expanduser("~/ida/plugins"),
        os.path.expanduser("~/TOOLS/idapro/plugins"),
        "/opt/ida/plugins",
        "C:\\Program Files\\IDA Pro 9.1\\plugins",
        "C:\\idapro\\plugins",
    ]
    
    for plugins_dir in ida_plugins_dirs:
        if not os.path.exists(plugins_dir): continue

        try:
            dest_path = os.path.join(plugins_dir, plugin_file)
            shutil.copy2(plugin_file, dest_path)
            print(f"Plugin installed to: {dest_path}")
            print("Restart IDA Pro to load the plugin")
            print("Use Ctrl+Shift+M to start/stop the MCP server")
            return True
        except Exception as e:
            print(f"Failed to copy to {plugins_dir}: {e}")
            continue
    
    print("IDA Pro plugins directory not found")
    print("Please manually copy ida_mcp_plugin.py to your IDA Pro plugins directory")
    return False

def main():
    parser = argparse.ArgumentParser(description="Install IDA Pro MCP plugin and configure VS Code")
    parser.add_argument("--server-path", 
                       help="Path to ida_mcp_server.py script (default: current directory)")
    parser.add_argument("--skip-vscode", action="store_true",
                       help="Skip VS Code configuration setup")
    
    args = parser.parse_args()
    
    if args.server_path:
        server_path = os.path.abspath(args.server_path)
    else:
        server_path = os.path.abspath("ida_mcp_server.py")
    
    if not os.path.exists(server_path):
        print(f"Error: Server file not found at {server_path}")
        return False
    
    print(f"Using MCP server path: {server_path}")
    
    plugin_success = install_plugin()
    
    vscode_success = True
    if not args.skip_vscode:
        print("\nSetting up VS Code configuration...")
        vscode_success = setup_vscode_config(server_path)
    
    if plugin_success and vscode_success:
        print("\nInstallation completed successfully!")
        return True
    else:
        print("\nInstallation completed with some issues.")
        return False

if __name__ == "__main__":
    main()
