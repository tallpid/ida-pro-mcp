#!/usr/bin/env python3

import json
import sys
import socket
import struct
import time

class IDAMCPBridge:
    def __init__(self, ida_host='localhost', ida_port=8765):
        self.ida_host = ida_host
        self.ida_port = ida_port
        self.ida_socket = None
        self.tools = {
            'ida_get_functions': {
                'name': 'ida_get_functions',
                'description': 'Get list of all functions in IDA Pro',
                'inputSchema': {
                    'type': 'object',
                    'properties': {},
                    'required': []
                }
            },
            'ida_get_function_info': {
                'name': 'ida_get_function_info',
                'description': 'Get detailed information about a specific function',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_get_strings': {
                'name': 'ida_get_strings',
                'description': 'Get list of all strings in IDA Pro',
                'inputSchema': {
                    'type': 'object',
                    'properties': {},
                    'required': []
                }
            },
            'ida_search_text': {
                'name': 'ida_search_text',
                'description': 'Search for text patterns in IDA Pro',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'pattern': {
                            'type': 'string',
                            'description': 'Text pattern to search for'
                        }
                    },
                    'required': ['pattern']
                }
            },
            'ida_get_segments': {
                'name': 'ida_get_segments',
                'description': 'Get list of memory segments',
                'inputSchema': {
                    'type': 'object',
                    'properties': {},
                    'required': []
                }
            },
            'ida_get_decompiler_output': {
                'name': 'ida_get_decompiler_output',
                'description': 'Get Hex-Rays decompiler output for a function',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_rename_function': {
                'name': 'ida_rename_function',
                'description': 'Rename a function at a specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        },
                        'name': {
                            'type': 'string',
                            'description': 'New function name (alphanumeric, underscores, and dollar signs only)'
                        }
                    },
                    'required': ['address', 'name']
                }
            },
            'ida_set_comment': {
                'name': 'ida_set_comment',
                'description': 'Set a comment at a specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Address in hex format (e.g., 0x401000)'
                        },
                        'comment': {
                            'type': 'string',
                            'description': 'Comment text to set'
                        }
                    },
                    'required': ['address', 'comment']
                }
            },
            'ida_get_comment': {
                'name': 'ida_get_comment',
                'description': 'Get comment at a specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_get_function_comments': {
                'name': 'ida_get_function_comments',
                'description': 'Get all comments within a function',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_set_function_type': {
                'name': 'ida_set_function_type',
                'description': 'Set function type/signature at specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        },
                        'type_string': {
                            'type': 'string',
                            'description': 'Function type string (e.g., "int __cdecl(int param1, char *param2)")'
                        }
                    },
                    'required': ['address', 'type_string']
                }
            },
            'ida_get_function_type': {
                'name': 'ida_get_function_type',
                'description': 'Get function type information and arguments',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_set_function_args': {
                'name': 'ida_set_function_args',
                'description': 'Set function arguments with types and names',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        },
                        'args': {
                            'type': 'array',
                            'description': 'Array of function arguments with type and name',
                            'items': {
                                'type': 'object',
                                'properties': {
                                    'type': {
                                        'type': 'string',
                                        'description': 'Argument type (e.g., "int", "char*", "void*")'
                                    },
                                    'name': {
                                        'type': 'string',
                                        'description': 'Argument name'
                                    }
                                }
                            }
                        }
                    },
                    'required': ['address', 'args']
                }
            },
            'ida_create_bookmark': {
                'name': 'ida_create_bookmark',
                'description': 'Create a bookmark at a specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Address in hex format (e.g., 0x401000)'
                        },
                        'description': {
                            'type': 'string',
                            'description': 'Bookmark description/comment'
                        }
                    },
                    'required': ['address', 'description']
                }
            },
            'ida_get_bookmarks': {
                'name': 'ida_get_bookmarks',
                'description': 'Get list of all bookmarks',
                'inputSchema': {
                    'type': 'object',
                    'properties': {},
                    'required': []
                }
            },
            'ida_delete_bookmark': {
                'name': 'ida_delete_bookmark',
                'description': 'Delete a bookmark at a specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_create_enum': {
                'name': 'ida_create_enum',
                'description': 'Create a new enum with specified values',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'description': 'Enum name'
                        },
                        'values': {
                            'type': 'array',
                            'description': 'Array of enum values with name and value',
                            'items': {
                                'type': 'object',
                                'properties': {
                                    'name': {
                                        'type': 'string',
                                        'description': 'Enum member name'
                                    },
                                    'value': {
                                        'type': ['integer', 'string'],
                                        'description': 'Enum member value (integer or hex string)'
                                    }
                                },
                                'required': ['name', 'value']
                            }
                        }
                    },
                    'required': ['name', 'values']
                }
            },
            'ida_get_enums': {
                'name': 'ida_get_enums',
                'description': 'Get list of all enums in the database',
                'inputSchema': {
                    'type': 'object',
                    'properties': {},
                    'required': []
                }
            },
            'ida_create_struct': {
                'name': 'ida_create_struct',
                'description': 'Create a new structure with specified fields',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'description': 'Structure name'
                        },
                        'fields': {
                            'type': 'array',
                            'description': 'Array of struct fields with name, type, and size',
                            'items': {
                                'type': 'object',
                                'properties': {
                                    'name': {
                                        'type': 'string',
                                        'description': 'Field name'
                                    },
                                    'type': {
                                        'type': 'string',
                                        'description': 'Field type (e.g., "int", "char*", "byte", "word", "dword", "qword")'
                                    },
                                    'size': {
                                        'type': 'integer',
                                        'description': 'Field size in bytes (optional, will be inferred from type if not provided)'
                                    }
                                },
                                'required': ['name', 'type']
                            }
                        }
                    },
                    'required': ['name', 'fields']
                }
            },
            'ida_get_structs': {
                'name': 'ida_get_structs',
                'description': 'Get list of all structures in the database',
                'inputSchema': {
                    'type': 'object',
                    'properties': {},
                    'required': []
                }
            },
            'ida_rename_variable': {
                'name': 'ida_rename_variable',
                'description': 'Rename a variable at a specific address',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Address in hex format (e.g., 0x401000)'
                        },
                        'old_name': {
                            'type': 'string',
                            'description': 'Current variable name'
                        },
                        'new_name': {
                            'type': 'string',
                            'description': 'New variable name (alphanumeric, underscores, and dollar signs only)'
                        }
                    },
                    'required': ['address', 'old_name', 'new_name']
                }
            },
            'ida_get_local_variables': {
                'name': 'ida_get_local_variables',
                'description': 'Get local variables for a function',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Function address in hex format (e.g., 0x401000)'
                        }
                    },
                    'required': ['address']
                }
            },
            'ida_set_variable_type': {
                'name': 'ida_set_variable_type',
                'description': 'Set the type of a variable',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'address': {
                            'type': 'string',
                            'description': 'Address in hex format (e.g., 0x401000)'
                        },
                        'var_name': {
                            'type': 'string',
                            'description': 'Variable name'
                        },
                        'var_type': {
                            'type': 'string',
                            'description': 'Variable type string (e.g., "int", "char*", "void*")'
                        }
                    },
                    'required': ['address', 'var_name', 'var_type']
                }
            }
        }

    def connect_to_ida(self):
        try:
            if self.ida_socket:
                self.ida_socket.close()
            self.ida_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ida_socket.connect((self.ida_host, self.ida_port))
            return True
        except Exception as e:
            self.ida_socket = None
            return False

    def send_ida_request(self, method: str, params=None):
        if not self.ida_socket:
            if not self.connect_to_ida():
                return {'error': 'Cannot connect to IDA Pro. Make sure IDA is running and MCP server is started (Ctrl+Shift+M)'}

        request = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {},
            'id': 1
        }

        try:
            request_data = json.dumps(request).encode('utf-8')
            request_length = struct.pack('>I', len(request_data))
            
            self.ida_socket.send(request_length + request_data)
            
            length_data = self.ida_socket.recv(4)
            if not length_data:
                return {'error': 'No response from IDA'}
            
            response_length = struct.unpack('>I', length_data)[0]
            response_data = self.ida_socket.recv(response_length)
            
            response = json.loads(response_data.decode('utf-8'))
            # Debug: Check what IDA actually returned
            if isinstance(response, dict):
                if 'result' in response:
                    return response['result']
                elif 'error' in response:
                    return response
                else:
                    return response
            else:
                return {'error': f'Unexpected response type: {type(response)}, content: {response}'}
        except Exception as e:
            self.ida_socket = None
            return {'error': f'IDA communication error: {str(e)}'}

    def hex_to_int(self, hex_str: str) -> int:
        if hex_str.startswith('0x'):
            return int(hex_str, 16)
        return int(hex_str, 16)

    def handle_request(self, request):
        method = request.get('method', '')
        params = request.get('params', {})
        request_id = request.get('id', 0)

        try:
            if method == 'initialize':
                return {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'result': {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {
                            'tools': {
                                'listChanged': False
                            }
                        },
                        'serverInfo': {
                            'name': 'IDA Pro MCP Server',
                            'version': '1.0.0'
                        }
                    }
                }
            
            elif method == 'tools/list':
                return {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'result': {
                        'tools': list(self.tools.values())
                    }
                }
            
            elif method == 'tools/call':
                tool_name = params.get('name', '')
                arguments = params.get('arguments', {})
                
                if tool_name == 'ida_get_functions':
                    result = self.send_ida_request('get_functions')
                elif tool_name == 'ida_get_function_info':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('get_function_info', {'address': address})
                elif tool_name == 'ida_get_strings':
                    result = self.send_ida_request('get_strings')
                elif tool_name == 'ida_search_text':
                    pattern = arguments.get('pattern', '')
                    result = self.send_ida_request('search_text', {'pattern': pattern})
                elif tool_name == 'ida_get_segments':
                    result = self.send_ida_request('get_segments')
                elif tool_name == 'ida_get_decompiler_output':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('get_decompiler_output', {'address': address})
                elif tool_name == 'ida_rename_function':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    name = arguments.get('name', '')
                    result = self.send_ida_request('rename_function', {'address': address, 'name': name})
                elif tool_name == 'ida_set_comment':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    comment = arguments.get('comment', '')
                    result = self.send_ida_request('set_comment', {'address': address, 'comment': comment})
                elif tool_name == 'ida_get_comment':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('get_comment', {'address': address})
                elif tool_name == 'ida_get_function_comments':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('get_function_comments', {'address': address})
                elif tool_name == 'ida_set_function_type':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    type_string = arguments.get('type_string', '')
                    result = self.send_ida_request('set_function_type', {'address': address, 'type_string': type_string})
                elif tool_name == 'ida_get_function_type':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('get_function_type', {'address': address})
                elif tool_name == 'ida_set_function_args':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    args = arguments.get('args', [])
                    result = self.send_ida_request('set_function_args', {'address': address, 'args': args})
                elif tool_name == 'ida_create_bookmark':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    description = arguments.get('description', '')
                    result = self.send_ida_request('create_bookmark', {'address': address, 'description': description})
                elif tool_name == 'ida_get_bookmarks':
                    result = self.send_ida_request('get_bookmarks')
                elif tool_name == 'ida_delete_bookmark':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('delete_bookmark', {'address': address})
                elif tool_name == 'ida_create_enum':
                    name = arguments.get('name', '')
                    values = arguments.get('values', [])
                    result = self.send_ida_request('create_enum', {'name': name, 'values': values})
                elif tool_name == 'ida_get_enums':
                    result = self.send_ida_request('get_enums')
                elif tool_name == 'ida_create_struct':
                    name = arguments.get('name', '')
                    fields = arguments.get('fields', [])
                    result = self.send_ida_request('create_struct', {'name': name, 'fields': fields})
                elif tool_name == 'ida_get_structs':
                    result = self.send_ida_request('get_structs')
                elif tool_name == 'ida_rename_variable':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    old_name = arguments.get('old_name', '')
                    new_name = arguments.get('new_name', '')
                    result = self.send_ida_request('rename_variable', {'address': address, 'old_name': old_name, 'new_name': new_name})
                elif tool_name == 'ida_get_local_variables':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    result = self.send_ida_request('get_local_variables', {'address': address})
                elif tool_name == 'ida_set_variable_type':
                    address = self.hex_to_int(arguments.get('address', '0'))
                    var_name = arguments.get('var_name', '')
                    var_type = arguments.get('var_type', '')
                    result = self.send_ida_request('set_variable_type', {'address': address, 'var_name': var_name, 'var_type': var_type})
                else:
                    result = {'error': f'Unknown tool: {tool_name}'}
                
                return {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'result': {
                        'content': [
                            {
                                'type': 'text',
                                'text': json.dumps(result, indent=2)
                            }
                        ]
                    }
                }
            
            else:
                return {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'error': {
                        'code': -32601,
                        'message': f'Method not found: {method}'
                    }
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

    def run(self):
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                
                request = json.loads(line.strip())
                response = self.handle_request(request)
                
                print(json.dumps(response), flush=True)
            
            except Exception as e:
                error_response = {
                    'jsonrpc': '2.0',
                    'id': None,
                    'error': {
                        'code': -32700,
                        'message': f'Parse error: {str(e)}'
                    }
                }
                print(json.dumps(error_response), flush=True)

if __name__ == '__main__':
    bridge = IDAMCPBridge()
    bridge.run()
