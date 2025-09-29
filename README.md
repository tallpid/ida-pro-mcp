IDA Pro MCP Plugin
===================

The following repo contains the IDA Pro MCP plugin, which is used to connect **Github Copilot** to IDA PRO. Tested against IDA Pro 9.1.x on Linux. 

* Install script copies the plugin to your IDA Pro plugins directory and MCP configuration to VSCode user settings. Call it as `python3 install.py`
* Make sure to reload VSCode and IDA Pro before use. 
* First start IDA Pro, then VSCode. To activate the plugin, press `Ctrl+Shift+M` in IDA.
* To access MCP functions from VSCode, use `#ida-pro` command in Copilot chat prompt.

Following functions are supported:

* `ida_get_functions` - List all functions in the current IDB. 
* `ida_get_function_info <function_ea>` - Get detailed information about a function by its EA.
* `ida_get_strings` - List all strings in the current IDB.
* `ida_search_text <search_term>` - Search for an ASCII string in the current IDB.
* `ida_get_segments` - List all segments in the current IDB.
* `ida_get_decompiler_output <function_ea>` - Get the decompiler output for a function by its EA.
* `ida_rename_function <function_ea> <new_name>` - Rename a function by its EA
* `ida_set_comment <address> <comment>` - Set a comment at a specific address
* `ida_get_comment <address>` - Get a comment at a specific address
* `ida_get_function_comments <function_ea>` - Get all comments in a function by its EA
* `ida_get_function_type <function_ea>` - Get the function prototype for a function by its EA
* `ida_set_function_args <function_ea> <arg1_type> <arg2_type> ...` - Set the argument types for a function by its EA
* `ida_create_bookmark <address> <bookmark_name>` - Create a bookmark at a specific address
* `ida_rename_variable <function_ea> <old_var_name> <new_var_name>` - Rename a local variable in a function by its EA
* `ida_set_variable_type <function_ea> <var_name> <new_type>` - Set the type of a local variable in a function by its EA

With minimal effort, it should be possible to port this plugin to Windows and MacOS. Pull requests are welcome!
