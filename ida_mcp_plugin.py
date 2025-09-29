import ida_kernwin
import ida_idaapi
import idautils
import idc
import ida_name
import ida_funcs
import ida_bytes
import ida_segment
import ida_hexrays
import ida_typeinf
import json
import socket
import threading
import struct
import time
from typing import Dict, List, Any, Optional

PLUGIN_NAME = "IDA MCP Plugin"
PLUGIN_VERSION = "0.1"

class IDAMCPServer:
    def __init__(self, port: int = 8765):
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None

    def start_server(self):
        if self.running:
            return
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('localhost', self.port))
            self.server_socket.listen(1)
            self.running = True
            
            self.thread = threading.Thread(target=self._server_loop, daemon=True)
            self.thread.start()
            
            print(f"IDA MCP Server started on port {self.port}")
        except Exception as e:
            print(f"Failed to start IDA MCP server: {e}")

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def _server_loop(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"MCP client connected from {addr}")
                self._handle_client(client_socket)
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}")

    def _handle_client(self, client_socket):
        while self.running:
            try:
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                
                message_length = struct.unpack('>I', length_data)[0]
                message_data = client_socket.recv(message_length)
                
                if not message_data:
                    break
                
                request = json.loads(message_data.decode('utf-8'))
                
                # Store result in a container that execute_sync can modify
                result_container = [None]
                
                def execute_request():
                    result_container[0] = self._handle_request(request)
                    return 0
                
                # Use ida_kernwin.execute_sync to run on main thread
                ida_kernwin.execute_sync(execute_request, ida_kernwin.MFF_FAST)
                response = result_container[0]
                
                response_data = json.dumps(response).encode('utf-8')
                response_length = struct.pack('>I', len(response_data))
                
                client_socket.send(response_length + response_data)
                
            except Exception as e:
                print(f"Client handling error: {e}")
                break
        
        client_socket.close()

    def _make_json_serializable(self, obj):
        """Convert IDA objects to JSON-serializable format"""
        if hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            return [str(item) for item in obj]
        return str(obj)

    def _handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get('method', '')
        params = request.get('params', {})
        request_id = request.get('id', 0)
        
        try:
            if method == 'get_functions':
                result = self._get_functions()
            elif method == 'get_function_info':
                result = self._get_function_info(params.get('address'))
            elif method == 'get_strings':
                result = self._get_strings()
            elif method == 'get_segments':
                result = self._get_segments()
            elif method == 'search_text':
                result = self._search_text(params.get('pattern'))
            elif method == 'get_decompiler_output':
                result = self._get_decompiler_output(params.get('address'))
            elif method == 'rename_function':
                result = self._rename_function(params.get('address'), params.get('name'))
            elif method == 'set_comment':
                result = self._set_comment(params.get('address'), params.get('comment'))
            elif method == 'get_comment':
                result = self._get_comment(params.get('address'))
            elif method == 'get_function_comments':
                result = self._get_function_comments(params.get('address'))
            elif method == 'set_function_type':
                result = self._set_function_type(params.get('address'), params.get('type_string'))
            elif method == 'get_function_type':
                result = self._get_function_type(params.get('address'))
            elif method == 'set_function_args':
                result = self._set_function_args(params.get('address'), params.get('args'))
            elif method == 'create_bookmark':
                result = self._create_bookmark(params.get('address'), params.get('description'))
            elif method == 'get_bookmarks':
                result = self._get_bookmarks()
            elif method == 'delete_bookmark':
                result = self._delete_bookmark(params.get('address'))
            elif method == 'create_enum':
                result = self._create_enum(params.get('name'), params.get('values'))
            elif method == 'get_enums':
                result = self._get_enums()
            elif method == 'create_struct':
                result = self._create_struct(params.get('name'), params.get('fields'))
            elif method == 'get_structs':
                result = self._get_structs()
            elif method == 'rename_variable':
                result = self._rename_variable(params.get('address'), params.get('old_name'), params.get('new_name'))
            elif method == 'get_local_variables':
                result = self._get_local_variables(params.get('address'))
            elif method == 'set_variable_type':
                result = self._set_variable_type(params.get('address'), params.get('var_name'), params.get('var_type'))
            elif method == 'reload_plugin':
                result = self._reload_plugin()
            else:
                result = {'error': f'Unknown method: {method}'}
            
            # Ensure result is JSON serializable
            try:
                json.dumps(result)
            except TypeError as e:
                result = {'error': f'JSON serialization error: {str(e)}', 'original_error': str(result)}
            
            return {
                'jsonrpc': '2.0',
                'id': request_id,
                'result': result
            }
        except Exception as e:
            return {
                'jsonrpc': '2.0',
                'id': request_id,
                'error': {
                    'code': -1,
                    'message': str(e)
                }
            }

    def _get_functions(self) -> List[Dict[str, Any]]:
        functions = []
        count = 0
        for func_ea in idautils.Functions():
            if count >= 100:
                break
            func = ida_funcs.get_func(func_ea)
            if func:
                name = ida_name.get_name(func_ea)
                functions.append({
                    'address': f'0x{func_ea:x}',
                    'name': name,
                    'start': f'0x{func.start_ea:x}',
                    'end': f'0x{func.end_ea:x}',
                    'size': func.end_ea - func.start_ea
                })
                count += 1
        return functions

    def _get_function_info(self, address: int) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        func = ida_funcs.get_func(address)
        if not func:
            return {'error': 'No function at address'}
        
        name = ida_name.get_name(func.start_ea)
        
        instructions = []
        count = 0
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if count >= 50:
                break
            disasm = idc.generate_disasm_line(head, 0)
            instructions.append({
                'address': f'0x{head:x}',
                'disasm': disasm
            })
            count += 1
        
        return {
            'address': f'0x{func.start_ea:x}',
            'name': name,
            'start': f'0x{func.start_ea:x}',
            'end': f'0x{func.end_ea:x}',
            'size': func.end_ea - func.start_ea,
            'instructions': instructions
        }

    def _get_strings(self) -> List[Dict[str, Any]]:
        strings = []
        count = 0
        for string in idautils.Strings():
            if count >= 100:
                break
            strings.append({
                'address': f'0x{string.ea:x}',
                'value': str(string)[:200],
                'length': string.length
            })
            count += 1
        return strings

    def _search_text(self, pattern: str) -> List[Dict[str, Any]]:
        if not pattern:
            return {'error': 'Pattern required'}
        
        results = []
        count = 0
        for seg_ea in idautils.Segments():
            if count >= 50:
                break
            seg = ida_segment.getseg(seg_ea)
            if seg:
                addr = seg.start_ea
                while addr < seg.end_ea and count < 50:
                    found_addr = idc.find_text(addr, 1, 0, pattern, 0) 
                    if found_addr == idc.BADADDR or found_addr >= seg.end_ea:
                        break
                    
                    results.append({
                        'address': f'0x{found_addr:x}',
                        'context': idc.generate_disasm_line(found_addr, 0)
                    })
                    addr = found_addr + 1
                    count += 1
        
        return results

    def _get_segments(self) -> List[Dict[str, Any]]:
        segments = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg:
                name = ida_segment.get_segm_name(seg)
                segments.append({
                    'address': f'0x{seg.start_ea:x}',
                    'name': name,
                    'start': f'0x{seg.start_ea:x}',
                    'end': f'0x{seg.end_ea:x}',
                    'size': seg.end_ea - seg.start_ea,
                    'permissions': seg.perm
                })
        return segments

    def _get_decompiler_output(self, address: int) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        try:
            # Check if Hex-Rays decompiler is available
            try:
                import ida_hexrays
                if not ida_hexrays.init_hexrays_plugin():
                    return {'error': 'Hex-Rays decompiler is not available or not licensed'}
            except ImportError:
                return {'error': 'Hex-Rays decompiler module not available (ida_hexrays not found)'}
            
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            # Get decompiled code
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {'error': 'Failed to decompile function - function may be too complex or contain unsupported constructs'}
            
            name = ida_name.get_name(func.start_ea)
            
            # Get function comments
            func_comment = idc.get_func_cmt(func.start_ea, 0)  # Regular comment
            func_repeatable_comment = idc.get_func_cmt(func.start_ea, 1)  # Repeatable comment
            
            # Get comments from instructions within the function
            instruction_comments = {}
            for head in idautils.Heads(func.start_ea, func.end_ea):
                comment = idc.get_cmt(head, 0)  # Regular comment
                repeatable_comment = idc.get_cmt(head, 1)  # Repeatable comment
                if comment or repeatable_comment:
                    instruction_comments[f'0x{head:x}'] = {
                        'regular': comment if comment else '',
                        'repeatable': repeatable_comment if repeatable_comment else ''
                    }
            
            return {
                'address': f'0x{func.start_ea:x}',
                'name': name,
                'start': f'0x{func.start_ea:x}',
                'end': f'0x{func.end_ea:x}',
                'decompiled_code': str(cfunc),
                'pseudocode_lines': [str(line) for line in cfunc.get_pseudocode()],
                'function_comment': func_comment if func_comment else '',
                'function_repeatable_comment': func_repeatable_comment if func_repeatable_comment else '',
                'instruction_comments': instruction_comments
            }
            
        except Exception as e:
            return {'error': f'Decompiler error: {str(e)}'}

    def _rename_function(self, address: int, new_name: str) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        if not new_name:
            return {'error': 'New name required'}
        
        # Validate the new name
        if not new_name.replace('_', '').replace('$', '').isalnum():
            return {'error': 'Invalid function name. Use only alphanumeric characters, underscores, and dollar signs'}
        
        func = ida_funcs.get_func(address)
        if not func:
            return {'error': 'No function at address'}
        
        old_name = ida_name.get_name(func.start_ea)
        
        # Set the new name
        if ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK):
            return {
                'address': f'0x{func.start_ea:x}',
                'old_name': old_name,
                'new_name': new_name,
                'success': True
            }
        else:
            return {
                'address': f'0x{func.start_ea:x}',
                'old_name': old_name,
                'error': 'Failed to rename function. Name might already exist or be invalid',
                'success': False
            }

    def _reload_plugin(self) -> Dict[str, Any]:
        try:
            # Stop the current server
            if self.running:
                self.running = False
                if self.server_socket:
                    self.server_socket.close()
            
            # Wait a moment then restart
            import time
            time.sleep(1)
            
            # Restart the server
            self.start_server()
            
            return {
                'success': True,
                'message': 'Plugin reloaded successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to reload plugin: {str(e)}'
            }

    def _set_comment(self, address: int, comment: str) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        if comment is None:
            comment = ""
        
        try:
            # Set regular comment at the address
            if idc.set_cmt(address, comment, 0):
                return {
                    'address': f'0x{address:x}',
                    'comment': comment,
                    'success': True,
                    'type': 'regular'
                }
            else:
                return {
                    'address': f'0x{address:x}',
                    'error': 'Failed to set comment',
                    'success': False
                }
        except Exception as e:
            return {'error': f'Comment error: {str(e)}'}

    def _get_comment(self, address: int) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        try:
            regular_comment = idc.get_cmt(address, 0)
            repeatable_comment = idc.get_cmt(address, 1)
            
            return {
                'address': f'0x{address:x}',
                'regular_comment': regular_comment if regular_comment else '',
                'repeatable_comment': repeatable_comment if repeatable_comment else '',
                'has_comment': bool(regular_comment or repeatable_comment)
            }
        except Exception as e:
            return {'error': f'Comment error: {str(e)}'}

    def _get_function_comments(self, address: int) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            name = ida_name.get_name(func.start_ea)
            
            # Get function-level comments
            func_comment = idc.get_func_cmt(func.start_ea, 0)
            func_repeatable_comment = idc.get_func_cmt(func.start_ea, 1)
            
            # Get all comments within the function
            comments = {}
            for head in idautils.Heads(func.start_ea, func.end_ea):
                regular_comment = idc.get_cmt(head, 0)
                repeatable_comment = idc.get_cmt(head, 1)
                
                if regular_comment or repeatable_comment:
                    disasm = idc.generate_disasm_line(head, 0)
                    comments[f'0x{head:x}'] = {
                        'disasm': disasm,
                        'regular_comment': regular_comment if regular_comment else '',
                        'repeatable_comment': repeatable_comment if repeatable_comment else ''
                    }
            
            return {
                'address': f'0x{func.start_ea:x}',
                'name': name,
                'start': f'0x{func.start_ea:x}',
                'end': f'0x{func.end_ea:x}',
                'function_comment': func_comment if func_comment else '',
                'function_repeatable_comment': func_repeatable_comment if func_repeatable_comment else '',
                'instruction_comments': comments,
                'total_comments': len(comments)
            }
        except Exception as e:
            return {'error': f'Comment error: {str(e)}'}

    def _set_function_type(self, address: int, type_string: str) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        if not type_string:
            return {'error': 'Type string required'}
        
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            old_name = ida_name.get_name(func.start_ea)
            
            # Parse and apply the function type
            if idc.parse_decl(type_string, idc.PT_TYP):
                if idc.apply_type(func.start_ea, idc.parse_decl(type_string, idc.PT_TYP)):
                    return {
                        'address': f'0x{func.start_ea:x}',
                        'name': old_name,
                        'type_string': type_string,
                        'success': True
                    }
                else:
                    return {
                        'address': f'0x{func.start_ea:x}',
                        'error': 'Failed to apply function type',
                        'success': False
                    }
            else:
                return {
                    'address': f'0x{func.start_ea:x}',
                    'error': 'Invalid type string format',
                    'success': False
                }
        except Exception as e:
            return {'error': f'Type setting error: {str(e)}'}

    def _get_function_type(self, address: int) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            name = ida_name.get_name(func.start_ea)
            
            # Get function type information
            func_type = idc.get_type(func.start_ea)
            
            # Get function signature if available
            func_signature = ""
            try:
                func_signature = idc.get_func_type_string(func.start_ea)
            except:
                pass
            
            # Try to get argument information using Hex-Rays if available
            args_info = []
            try:
                import ida_hexrays
                if ida_hexrays.init_hexrays_plugin():
                    cfunc = ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        # Get function arguments from decompiled function
                        for i in range(cfunc.type.get_nargs()):
                            arg_type = cfunc.type.get_nth_arg(i)
                            arg_name = f"arg_{i}"
                            if cfunc.lvars and i < len(cfunc.lvars):
                                if hasattr(cfunc.lvars[i], 'name'):
                                    arg_name = cfunc.lvars[i].name
                            args_info.append({
                                'index': i,
                                'name': arg_name,
                                'type': str(arg_type) if arg_type else 'unknown'
                            })
            except:
                pass
            
            return {
                'address': f'0x{func.start_ea:x}',
                'name': name,
                'start': f'0x{func.start_ea:x}',
                'end': f'0x{func.end_ea:x}',
                'type_string': func_type if func_type else '',
                'signature': func_signature if func_signature else '',
                'arguments': args_info,
                'argument_count': len(args_info)
            }
        except Exception as e:
            return {'error': f'Type retrieval error: {str(e)}'}

    def _set_function_args(self, address: int, args: List[Dict[str, str]]) -> Dict[str, Any]:
        if not address:
            return {'error': 'Address required'}
        
        if not args or not isinstance(args, list):
            return {'error': 'Arguments list required'}
        
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            name = ida_name.get_name(func.start_ea)
            
            # Build function type string from arguments
            arg_strings = []
            for i, arg in enumerate(args):
                arg_type = arg.get('type', 'int')
                arg_name = arg.get('name', f'arg_{i}')
                arg_strings.append(f"{arg_type} {arg_name}")
            
            return_type = "int"  # Default return type
            if args and 'return_type' in args[0]:
                return_type = args[0]['return_type']
            
            # Construct function declaration
            args_string = ", ".join(arg_strings)
            func_decl = f"{return_type} {name}({args_string})"
            
            # Apply the function type
            if idc.parse_decl(func_decl, idc.PT_FUNC):
                if idc.apply_type(func.start_ea, idc.parse_decl(func_decl, idc.PT_FUNC)):
                    return {
                        'address': f'0x{func.start_ea:x}',
                        'name': name,
                        'function_declaration': func_decl,
                        'arguments': args,
                        'success': True
                    }
                else:
                    return {
                        'address': f'0x{func.start_ea:x}',
                        'error': 'Failed to apply function arguments',
                        'success': False
                    }
            else:
                return {
                    'address': f'0x{func.start_ea:x}',
                    'error': f'Invalid function declaration: {func_decl}',
                    'success': False
                }
        except Exception as e:
            return {'error': f'Argument setting error: {str(e)}'}

    def _create_bookmark(self, address: int, description: str) -> Dict[str, Any]:
        """Create a bookmark at the specified address with the given description"""
        if not address:
            return {'error': 'Address required'}
        
        if not description:
            return {'error': 'Description required'}
        
        try:
            # Convert string address to integer if needed
            if isinstance(address, str):
                if address.startswith('0x'):
                    address = int(address, 16)
                else:
                    address = int(address)
            
            # In IDA Pro, bookmarks are typically implemented as special comments
            # We'll use a prefix to identify bookmark comments
            bookmark_comment = f"BOOKMARK: {description}"
            
            # Set the comment at the address
            if idc.set_cmt(address, bookmark_comment, 0):  # 0 = regular comment
                return {
                    'address': f'0x{address:x}',
                    'description': description,
                    'success': True,
                    'message': 'Bookmark created successfully'
                }
            else:
                return {
                    'address': f'0x{address:x}',
                    'error': 'Failed to create bookmark comment',
                    'success': False
                }
        except Exception as e:
            return {'error': f'Bookmark creation error: {str(e)}'}

    def _get_bookmarks(self) -> Dict[str, Any]:
        """Get list of all bookmarks in the database"""
        try:
            bookmarks = []
            
            # Iterate through all segments to find bookmark comments
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg:
                    # Iterate through all addresses in the segment
                    for head in idautils.Heads(seg.start_ea, seg.end_ea):
                        comment = idc.get_cmt(head, 0)  # Regular comment
                        if comment and comment.startswith('BOOKMARK:'):
                            # Extract the description from the bookmark comment
                            description = comment[9:].strip()  # Remove "BOOKMARK:" prefix
                            
                            # Get additional context
                            disasm = idc.generate_disasm_line(head, 0)
                            func = ida_funcs.get_func(head)
                            func_name = ""
                            if func:
                                func_name = ida_name.get_name(func.start_ea)
                            
                            bookmarks.append({
                                'address': f'0x{head:x}',
                                'description': description,
                                'disasm': disasm,
                                'function': func_name,
                                'segment': ida_segment.get_segm_name(seg)
                            })
            
            return {
                'bookmarks': bookmarks,
                'count': len(bookmarks),
                'success': True
            }
        except Exception as e:
            return {'error': f'Bookmark retrieval error: {str(e)}'}

    def _delete_bookmark(self, address: int) -> Dict[str, Any]:
        """Delete a bookmark at the specified address"""
        if not address:
            return {'error': 'Address required'}
        
        try:
            # Convert string address to integer if needed
            if isinstance(address, str):
                if address.startswith('0x'):
                    address = int(address, 16)
                else:
                    address = int(address)
            
            # Check if there's a bookmark at this address
            comment = idc.get_cmt(address, 0)
            if not comment or not comment.startswith('BOOKMARK:'):
                return {
                    'address': f'0x{address:x}',
                    'error': 'No bookmark found at this address',
                    'success': False
                }
            
            # Delete the bookmark comment
            if idc.set_cmt(address, "", 0):  # Set empty comment to delete
                return {
                    'address': f'0x{address:x}',
                    'success': True,
                    'message': 'Bookmark deleted successfully'
                }
            else:
                return {
                    'address': f'0x{address:x}',
                    'error': 'Failed to delete bookmark',
                    'success': False
                }
        except Exception as e:
            return {'error': f'Bookmark deletion error: {str(e)}'}

    def _create_enum(self, enum_name: str, values: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new enum with specified values"""
        if not enum_name:
            return {'error': 'Enum name required'}
        
        if not values or not isinstance(values, list):
            return {'error': 'Values list required'}
        
        try:
            # Check if enum already exists
            enum_id = idc.get_enum(enum_name)
            if enum_id != ida_idaapi.BADADDR:
                return {'error': f'Enum "{enum_name}" already exists'}
            
            # Create the enum
            enum_id = idc.add_enum(ida_idaapi.BADADDR, enum_name, idc.hex_flag())
            if enum_id == ida_idaapi.BADADDR:
                return {'error': 'Failed to create enum'}
            
            # Add values to the enum
            added_values = []
            for value_info in values:
                if not isinstance(value_info, dict):
                    continue
                    
                val_name = value_info.get('name', '')
                val_value = value_info.get('value', 0)
                
                if not val_name:
                    continue
                
                # Convert string value to integer if needed
                if isinstance(val_value, str):
                    if val_value.startswith('0x'):
                        val_value = int(val_value, 16)
                    else:
                        val_value = int(val_value)
                
                # Add the enum member
                if idc.add_enum_member(enum_id, val_name, val_value, ida_idaapi.BADADDR) == 0:
                    added_values.append({
                        'name': val_name,
                        'value': val_value
                    })
            
            return {
                'enum_name': enum_name,
                'enum_id': f'0x{enum_id:x}',
                'values': added_values,
                'success': True,
                'message': f'Enum "{enum_name}" created with {len(added_values)} values'
            }
            
        except Exception as e:
            return {'error': f'Enum creation error: {str(e)}'}

    def _get_enums(self) -> Dict[str, Any]:
        """Get list of all enums in the database"""
        try:
            enums = []
            
            # Get all enums using idc functions
            for enum_idx in range(idc.get_enum_qty()):
                enum_id = idc.getn_enum(enum_idx)
                if enum_id != ida_idaapi.BADADDR:
                    enum_name = idc.get_enum_name(enum_id)
                    
                    # Get enum members
                    members = []
                    # Get first member
                    first_member = idc.get_first_enum_member(enum_id)
                    if first_member != ida_idaapi.BADADDR:
                        member_name = idc.get_enum_member_name(first_member)
                        member_value = idc.get_enum_member_value(first_member)
                        members.append({
                            'name': member_name,
                            'value': member_value
                        })
                        
                        # Get subsequent members
                        next_member = first_member
                        while True:
                            next_member = idc.get_next_enum_member(enum_id, next_member)
                            if next_member == ida_idaapi.BADADDR:
                                break
                            member_name = idc.get_enum_member_name(next_member)
                            member_value = idc.get_enum_member_value(next_member)
                            members.append({
                                'name': member_name,
                                'value': member_value
                            })
                    
                    enums.append({
                        'id': f'0x{enum_id:x}',
                        'name': enum_name,
                        'members': members
                    })
            
            return {
                'enums': enums,
                'total_count': len(enums),
                'success': True
            }
            
        except Exception as e:
            return {'error': f'Enum retrieval error: {str(e)}'}

    def _create_struct(self, struct_name: str, fields: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new structure with specified fields"""
        if not struct_name:
            return {'error': 'Structure name required'}
        
        if not fields or not isinstance(fields, list):
            return {'error': 'Fields list required'}
        
        try:
            # Check if struct already exists
            struct_id = idc.get_struc_id(struct_name)
            if struct_id != ida_idaapi.BADADDR:
                return {'error': f'Structure "{struct_name}" already exists'}
            
            # Create the structure
            struct_id = idc.add_struc(ida_idaapi.BADADDR, struct_name, 0)
            if struct_id == ida_idaapi.BADADDR:
                return {'error': 'Failed to create structure'}
            
            # Add fields to the structure
            added_fields = []
            current_offset = 0
            
            for field_info in fields:
                if not isinstance(field_info, dict):
                    continue
                    
                field_name = field_info.get('name', '')
                field_type = field_info.get('type', 'int')
                field_size = field_info.get('size', 4)
                
                if not field_name:
                    continue
                
                # Map common types to IDA flags and sizes
                type_flags = ida_bytes.FF_DATA
                if field_type == 'byte':
                    type_flags |= ida_bytes.FF_BYTE
                    field_size = 1
                elif field_type == 'word':
                    type_flags |= ida_bytes.FF_WORD
                    field_size = 2
                elif field_type == 'dword' or field_type == 'int':
                    type_flags |= ida_bytes.FF_DWORD
                    field_size = 4
                elif field_type == 'qword':
                    type_flags |= ida_bytes.FF_QWORD
                    field_size = 8
                elif field_type.endswith('*'):
                    type_flags |= ida_bytes.FF_POINTER
                    field_size = 8 if ida_idaapi.get_inf_structure().is_64bit() else 4
                
                # Add the field to the structure using idc
                if idc.add_struc_member(struct_id, field_name, current_offset, type_flags, ida_idaapi.BADADDR, field_size) == 0:
                    added_fields.append({
                        'name': field_name,
                        'type': field_type,
                        'offset': current_offset,
                        'size': field_size
                    })
                    current_offset += field_size
            
            return {
                'struct_name': struct_name,
                'struct_id': f'0x{struct_id:x}',
                'fields': added_fields,
                'total_size': current_offset,
                'success': True,
                'message': f'Structure "{struct_name}" created with {len(added_fields)} fields'
            }
            
        except Exception as e:
            return {'error': f'Structure creation error: {str(e)}'}

    def _get_structs(self) -> Dict[str, Any]:
        """Get list of all structures in the database"""
        try:
            structs = []
            
            # Get all structures using idc functions
            for struct_idx in range(idc.get_struc_qty()):
                struct_id = idc.get_struc_by_idx(struct_idx)
                if struct_id != ida_idaapi.BADADDR:
                    struct_name = idc.get_struc_name(struct_id)
                    struct_size = idc.get_struc_size(struct_id)
                    
                    # Get struct members
                    members = []
                    member_qty = idc.get_member_qty(struct_id)
                    for i in range(member_qty):
                        member_name = idc.get_member_name(struct_id, i)
                        member_offset = idc.get_member_offset(struct_id, member_name)
                        member_size = idc.get_member_size(struct_id, i)
                        if member_name:
                            members.append({
                                'name': member_name,
                                'offset': member_offset,
                                'size': member_size
                            })
                    
                    structs.append({
                        'id': f'0x{struct_id:x}',
                        'name': struct_name,
                        'size': struct_size,
                        'members': members
                    })
            
            return {
                'structs': structs,
                'total_count': len(structs),
                'success': True
            }
            
        except Exception as e:
            return {'error': f'Structure retrieval error: {str(e)}'}

    def _rename_variable(self, address: int, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a variable at a specific address"""
        if not address:
            return {'error': 'Address required'}
        
        if not old_name:
            return {'error': 'Old variable name required'}
        
        if not new_name:
            return {'error': 'New variable name required'}
        
        try:
            # Validate the new name
            if not new_name.replace('_', '').replace('$', '').isalnum():
                return {'error': 'Invalid variable name. Use only alphanumeric characters, underscores, and dollar signs'}
            
            # Check if we're in a function
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'Address is not within a function'}
            
            # Try to rename using IDA's naming functions
            if ida_name.set_name(address, new_name, ida_name.SN_CHECK):
                return {
                    'address': f'0x{address:x}',
                    'old_name': old_name,
                    'new_name': new_name,
                    'success': True,
                    'message': f'Variable renamed from "{old_name}" to "{new_name}"'
                }
            else:
                return {
                    'address': f'0x{address:x}',
                    'old_name': old_name,
                    'error': 'Failed to rename variable. Name might already exist or be invalid',
                    'success': False
                }
            
        except Exception as e:
            return {'error': f'Variable renaming error: {str(e)}'}

    def _get_local_variables(self, address: int) -> Dict[str, Any]:
        """Get local variables for a function"""
        if not address:
            return {'error': 'Address required'}
        
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            func_name = ida_name.get_name(func.start_ea)
            variables = []
            
            # Try to get variables using Hex-Rays if available
            try:
                import ida_hexrays
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc:
                    # Get local variables from decompiler
                    for var in cfunc.lvars:
                        variables.append({
                            'name': var.name,
                            'type': str(var.type()),
                            'location': 'stack' if var.is_stk_var() else 'register',
                            'offset': var.location.stkoff() if var.is_stk_var() else None
                        })
            except (ImportError, Exception):
                pass
            
            # Also try to get stack frame information using idc
            try:
                frame_id = idc.get_frame_id(func.start_ea)
                if frame_id != ida_idaapi.BADADDR:
                    frame_size = idc.get_struc_size(frame_id)
                    member_qty = idc.get_member_qty(frame_id)
                    for i in range(member_qty):
                        member_name = idc.get_member_name(frame_id, i)
                        member_offset = idc.get_member_offset(frame_id, member_name)
                        member_size = idc.get_member_size(frame_id, i)
                        if member_name and not any(v['name'] == member_name for v in variables):
                            variables.append({
                                'name': member_name,
                                'type': 'unknown',
                                'location': 'stack',
                                'offset': member_offset,
                                'size': member_size
                            })
            except Exception:
                pass
            
            return {
                'function_address': f'0x{func.start_ea:x}',
                'function_name': func_name,
                'variables': variables,
                'total_count': len(variables),
                'success': True
            }
            
        except Exception as e:
            return {'error': f'Variable retrieval error: {str(e)}'}

    def _set_variable_type(self, address: int, var_name: str, var_type: str) -> Dict[str, Any]:
        """Set the type of a variable"""
        if not address:
            return {'error': 'Address required'}
        
        if not var_name:
            return {'error': 'Variable name required'}
        
        if not var_type:
            return {'error': 'Variable type required'}
        
        try:
            func = ida_funcs.get_func(address)
            if not func:
                return {'error': 'No function at address'}
            
            # Try to set variable type using Hex-Rays if available
            try:
                import ida_hexrays
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc:
                    # Find the variable in the function
                    for var in cfunc.lvars:
                        if var.name == var_name:
                            # Try to parse the type string
                            try:
                                # Simple type mapping
                                if var_type == 'int':
                                    var.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
                                elif var_type == 'char*':
                                    var.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR | ida_typeinf.BTF_PTR)
                                elif var_type == 'void*':
                                    var.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID | ida_typeinf.BTF_PTR)
                                
                                return {
                                    'address': f'0x{address:x}',
                                    'variable_name': var_name,
                                    'new_type': var_type,
                                    'success': True,
                                    'message': f'Variable "{var_name}" type set to "{var_type}"'
                                }
                            except Exception as type_err:
                                return {
                                    'address': f'0x{address:x}',
                                    'variable_name': var_name,
                                    'error': f'Failed to set type: {str(type_err)}',
                                    'success': False
                                }
            except ImportError:
                pass
            
            return {
                'address': f'0x{address:x}',
                'variable_name': var_name,
                'error': 'Could not set variable type. Hex-Rays decompiler may not be available',
                'success': False
            }
            
        except Exception as e:
            return {'error': f'Variable type setting error: {str(e)}'}


class IDAMCPPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "MCP Server for IDA Pro"
    help = "Provides MCP connection to IDA Pro"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Shift-M"

    def __init__(self):
        self.mcp_server = None

    def init(self):
        print(f"{PLUGIN_NAME} v{PLUGIN_VERSION} loaded")
        print(f"!!! Press Ctrl+Shift+M to start/stop the MCP server !!!")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.mcp_server and self.mcp_server.running:
            self.mcp_server.stop_server()
            self.mcp_server = None
            print("IDA MCP Server stopped")
        else:
            self.mcp_server = IDAMCPServer()
            self.mcp_server.start_server()

    def term(self):
        if self.mcp_server:
            self.mcp_server.stop_server()
        print(f"{PLUGIN_NAME} unloaded")


def PLUGIN_ENTRY():
    return IDAMCPPlugin()
