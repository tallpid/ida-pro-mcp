#!/usr/bin/env python3

import os
import shutil
import sys
import json
import argparse

def setup_vscode_config(server_path):
    config_file = os.path.expanduser("~/.config/Code/User/mcp.json")
    
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    
    # Read existing config if it exists
    existing_config = {"servers": {}, "inputs": {}}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                existing_config = json.load(f)
                # Ensure required keys exist
                if "servers" not in existing_config:
                    existing_config["servers"] = {}
                if "inputs" not in existing_config:
                    existing_config["inputs"] = {}
        except Exception as e:
            print(f"Warning: Could not read existing config ({e}), will create new one")
    
    # Add or update ida-pro server configuration
    existing_config["servers"]["ida-pro"] = {
        "type": "stdio",
        "command": "python3",
        "args": [server_path],
        "env": {}
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(existing_config, f, indent=2)
        print(f"MCP server configuration updated to: {config_file}")
        print("Restart VS Code completely and try:")
        print("   @ida ida_get_functions")
        print("   @ida ida_get_function_info address=0x401000")
        print("   @ida ida_get_xrefs name=printf")
        return True
    except Exception as e:
        print(f"Failed to write VS Code config: {e}")
        return False

def install_plugin(plugins_dir):
    plugin_file = "ida_mcp_plugin.py"
    
    if not os.path.exists(plugin_file):
        print(f"Error: {plugin_file} not found")
        return False
    
    # Expand user path and validate
    plugins_dir = os.path.expanduser(plugins_dir)
    if not os.path.exists(plugins_dir):
        print(f"Error: Plugins directory does not exist: {plugins_dir}")
        return False
    
    try:
        dest_path = os.path.join(plugins_dir, plugin_file)
        shutil.copy2(plugin_file, dest_path)
        print(f"Plugin installed to: {dest_path}")
        print("Restart IDA Pro to load the plugin")
        print("Use Ctrl+Shift+M to start/stop the MCP server")
        return True
    except Exception as e:
        print(f"Failed to copy to {plugins_dir}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Install IDA Pro MCP plugin and configure VS Code")
    parser.add_argument("ida_plugins_dir",
                       help="Path to IDA Pro plugins directory")
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
    
    # Install plugin to specified directory
    plugin_success = install_plugin(args.ida_plugins_dir)
    
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
