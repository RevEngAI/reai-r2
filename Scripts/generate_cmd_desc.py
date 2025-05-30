#!/usr/bin/env python3
# Generate CmdDesc.h and CmdDesc.c from YAML command descriptions
# Copyright (c) 2024 RevEngAI. All Rights Reserved.

import os
import sys
import yaml
import glob
import time
from datetime import datetime

def camel_to_snake(name):
    """Convert camelCase to snake_case"""
    import re
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

def load_commands():
    """Load commands from YAML files"""
    commands = []
    command_groups = {}
    dual_role_commands = {}  # Commands that are both groups and individual commands
    
    # Load all YAML files
    yaml_files = glob.glob(os.path.join('Source', 'Radare', 'CmdDesc', '*.yaml'))
    
    for yaml_file in yaml_files:
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
            
        if not data or 'group' not in data or 'commands' not in data:
            continue
            
        group_name = data['group']
        group_commands = data['commands']
        
        # Store commands for this group
        command_groups[group_name] = group_commands
        
        # Add all commands to the main list
        for cmd in group_commands:
            cmd['parent'] = group_name
            commands.append(cmd)
            
            # Check if this command has the same name as its group
            if cmd['name'] == group_name:
                dual_role_commands[group_name] = cmd
    
    # Detect nested command groups by finding commands that are prefixes of other commands
    nested_groups = {}
    all_command_names = [cmd['name'] for cmd in commands]
    
    for cmd in commands:
        cmd_name = cmd['name']
        # Find commands that start with this command name (but are longer)
        subcommands = [name for name in all_command_names 
                      if name.startswith(cmd_name) and len(name) > len(cmd_name)]
        
        # If this command has subcommands, it's a nested group
        if subcommands:
            nested_groups[cmd_name] = [c for c in commands if c['name'] in subcommands]
            # Add to command_groups
            command_groups[cmd_name] = nested_groups[cmd_name]
    
    return commands, command_groups, dual_role_commands

def generate_header_file(commands, command_groups, dual_role_commands):
    """Generate CmdDesc.h"""
    current_date = time.strftime('%d %B %Y')
    
    # Handler declarations
    handler_declarations = []
    for cmd in commands:
        if 'cname' in cmd:
            cmd_name = cmd['name']
            # Include handler if it's not a group, OR if it's a dual-role command (both group and individual command)
            if cmd_name not in command_groups or cmd_name in dual_role_commands:
                handler_declarations.append(f"R_API RCmdStatus r_{cmd['cname']}_handler(RCore* core, int argc, const char** argv);")
    
    # Dispatcher declarations  
    dispatcher_declarations = []
    processed = set()
    
    # Add dispatchers for all individual commands (not groups)
    for cmd in commands:
        if 'cname' in cmd:
            cmd_name = cmd['name']
            # Include dispatcher if it's not a group, OR if it's a dual-role command
            if (cmd_name not in command_groups or cmd_name in dual_role_commands) and cmd_name not in processed:
                dispatcher_declarations.append(f"R_IPI RCmdStatus r_{cmd['cname']}_dispatcher(RCore* core, int argc, const char** argv);")
                processed.add(cmd_name)
    
    # Add dispatchers for command groups
    for group_name in command_groups:
        if group_name not in processed:
            group_cname = camel_to_snake(group_name)
            dispatcher_declarations.append(f"R_IPI RCmdStatus r_{group_cname}_dispatcher(RCore* core, int argc, const char** argv);")
            processed.add(group_name)
    
    # Help function declarations
    help_declarations = []
    help_declarations.append("void print_root_help(void);")
    
    # Individual command help functions
    for cmd in commands:
        if 'cname' in cmd:
            help_declarations.append(f"void print_{cmd['cname']}_help(void);")
    
    # Group help functions
    for group_name in command_groups:
        group_cname = camel_to_snake(group_name)
        help_declarations.append(f"void print_{group_cname}_group_help(void);")
        
        # Dual help functions for groups with same-named commands
        if group_name in dual_role_commands:
            help_declarations.append(f"void print_{group_name}_dual_help(void);")
    
    header_content = f"""/**
 * @file : CmdDesc.h
 * @date : {current_date}
 * @author : Generated from YAML command descriptions
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef RADARE_CMD_DESC_H
#define RADARE_CMD_DESC_H

#include <r_core.h>

/* Global command dispatcher - entry point for all commands */
R_API RCmdStatus reai_global_command_dispatcher(RCore* core, const char* command);

/* General help handler - for backward compatibility */
R_API RCmdStatus r_show_help_handler(RCore* core, int argc, const char** argv);

/* Handler function declarations - implement these in CmdHandlers.c */
{chr(10).join(handler_declarations)}

/* Command dispatcher declarations - implementations in CmdDesc.c */
{chr(10).join(dispatcher_declarations)}

/* Help printer function declarations */
{chr(10).join(help_declarations)}

#endif /* RADARE_CMD_DESC_H */
"""
    
    return header_content

def generate_help_implementations(commands, command_groups, dual_role_commands):
    """Generate help function implementations"""
    implementations = []
    
    # Root help
    implementations.append("""/**
 * Print root level help for all commands
 */
void print_root_help(void) {
    r_cons_println("RevEngAI Radare2 Plugin - Command Help");
    r_cons_println("=======================================");
    r_cons_println("REi      - Initialize plugin config with API key");
    r_cons_println("REm      - List all available AI models for RevEngAI analysis");
    r_cons_println("REh      - Check connection status with RevEngAI servers");
    r_cons_println("REu      - Upload binary to RevEngAI servers");
    r_cons_println("REd      - Decompile function using RevEngAI's AI Decompiler");
    r_cons_println("REart    - Show RevEng.AI ASCII art");""")
    
    # Add group commands to root help
    for group_name in command_groups:
        # Find the summary for this group
        group_summary = f"Commands for {group_name} operations"
        for cmd in commands:
            if cmd.get('name') == group_name and 'parent' not in cmd:
                group_summary = cmd.get('summary', group_summary)
                break
        implementations[-1] += f'\n    r_cons_println("{group_name:<8} - {group_summary}");'
    
    implementations[-1] += '''
    r_cons_println("");
    r_cons_println("Use <command>? to get detailed help for a specific command");
    r_cons_println("Use <command>?? to get detailed help for specific command (not group)");
}
'''

    # Individual command help functions - avoid duplicates
    processed_help_functions = set()
    for cmd in commands:
        if 'cname' not in cmd:
            continue
            
        cmd_name = cmd['name']
        cname = cmd['cname']
        
        # Skip if we've already processed this help function
        if cname in processed_help_functions:
            continue
        processed_help_functions.add(cname)
        
        summary = cmd.get('summary', '')
        args = cmd.get('args', [])
        
        # Build usage string
        usage = cmd_name
        for arg in args:
            arg_name = arg['name']
            if arg.get('optional', False):
                usage += f" [<{arg_name}>]"
            else:
                usage += f" <{arg_name}>"
        usage += f" # {summary}"
        
        help_impl = f"""/**
 * Print help for {cmd_name} command
 */
void print_{cname}_help(void) {{
    r_cons_println("{usage}");"""
        
        # Add examples if present
        details = cmd.get('details', [])
        for detail in details:
            if detail.get('name') == 'Examples':
                help_impl += '\n    r_cons_println("\\nExamples:");'
                for entry in detail.get('entries', []):
                    text = entry.get('text', '').replace('"', '\\"')
                    comment = entry.get('comment', '').replace('"', '\\"')
                    help_impl += f'\n    r_cons_println("{text}  # {comment}");'
        
        help_impl += '\n}\n'
        implementations.append(help_impl)
    
    # Group help functions
    for group_name, group_commands in command_groups.items():
        group_cname = camel_to_snake(group_name)
        
        help_impl = f"""/**
 * Print help for {group_name} command group
 */
void print_{group_cname}_group_help(void) {{
    r_cons_println("{group_name} Command Group");
    r_cons_println("{'=' * (len(group_name) + 14)}");"""
        
        # Filter commands to show only top-level ones (not subcommands of nested groups)
        commands_to_show = []
        nested_group_prefixes = [cmd_name for cmd_name in command_groups.keys() 
                                if cmd_name != group_name and cmd_name.startswith(group_name)]
        
        for cmd in sorted(group_commands, key=lambda x: x.get('name', '')):
            cmd_name = cmd.get('name', '')
            summary = cmd.get('summary', '')
            
            # Skip this command if it's a subcommand of a nested group
            is_subcommand = False
            for prefix in nested_group_prefixes:
                if cmd_name.startswith(prefix) and len(cmd_name) > len(prefix):
                    is_subcommand = True
                    break
            
            if not is_subcommand:
                commands_to_show.append((cmd_name, summary))
        
        # Add commands to help
        for cmd_name, summary in commands_to_show:
            help_impl += f'\n    r_cons_println("{cmd_name:<12} - {summary}");'
        
        help_impl += '''
    r_cons_println("");
    r_cons_println("Use <command>? to get detailed help for a specific command");
}
'''
        implementations.append(help_impl)
        
        # Dual help functions for groups with same-named commands
        if group_name in dual_role_commands:
            dual_cmd = dual_role_commands[group_name]
            dual_cname = dual_cmd['cname']
            
            # Calculate separator length
            separator_len = len('Available commands in ' + group_name + ' group:')
            separator = '=' * separator_len
            
            dual_help = f"""/**
 * Print dual help for {group_name} (both group and command)
 */
void print_{group_name}_dual_help(void) {{
    r_cons_println("{group_name} - Dual Role Command");
    r_cons_println("{'=' * (len(group_name) + 19)}");
    r_cons_println("This command has two roles:");
    r_cons_println("");
    r_cons_println("1. As a command group:");
    r_cons_println("   Contains subcommands for {group_name} operations");
    r_cons_println("   Use '{group_name}?' to see group help");
    r_cons_println("");
    r_cons_println("2. As a specific command:");
    r_cons_println("   {dual_cmd.get('summary', '')}");
    r_cons_println("   Use '{group_name}' followed by two question marks to see command-specific help");
    r_cons_println("");
    r_cons_println("Available commands in {group_name} group:");
    r_cons_println("{separator}");"""
            
            # Add all commands in the group to the dual help
            for cmd in sorted(group_commands, key=lambda x: x.get('name', '')):
                cmd_name = cmd.get('name', '')
                summary = cmd.get('summary', '')
                dual_help += f'\n    r_cons_println("{cmd_name:<12} - {summary}");'
            
            dual_help += """
    r_cons_println("");
    r_cons_println("Use <command>? to get detailed help for a specific command");
}
"""
            implementations.append(dual_help)
    
    return '\n'.join(implementations)

def generate_dispatchers(commands, command_groups, dual_role_commands):
    """Generate dispatcher implementations"""
    implementations = []
    processed = set()
    
    # Root command dispatchers
    for cmd in commands:
        if 'cname' not in cmd:
            continue
            
        cmd_name = cmd['name']
        # Skip if this is a group command or already processed, UNLESS it's a dual-role command
        if (cmd_name in command_groups and cmd_name not in dual_role_commands) or cmd_name in processed:
            continue
        processed.add(cmd_name)
        
        cname = cmd['cname']
        summary = cmd.get('summary', '')
        args = cmd.get('args', [])
        
        # Count required args
        required_count = sum(1 for arg in args if not arg.get('optional', False))
        
        impl = f"""/**
 * "{cmd_name}" - Dispatcher
 * {summary}
 */
R_IPI RCmdStatus r_{cname}_dispatcher(RCore* core, int argc, const char** argv) {{
    // Check if this is a help command (ends with ? or ??)
    if (argc > 0 && is_help_command(argv[0])) {{
        print_{cname}_help();
        return R_CMD_STATUS_OK;
    }}

    // Validate command arguments - if insufficient, show help and return error
    if (!validate_arguments(core, argc, argv, {required_count}, "{cmd_name}", NULL, NULL)) {{
        print_{cname}_help();
        return R_CMD_STATUS_WRONG_ARGS;
    }}

    // Call the actual handler function
    return r_{cname}_handler(core, argc, argv);
}}
"""
        implementations.append(impl)
    
    # Group dispatchers
    for group_name, group_commands in command_groups.items():
        if group_name in processed:
            continue
        processed.add(group_name)
        
        group_cname = camel_to_snake(group_name)
        
        # Check if this group has a dual-role command
        if group_name in dual_role_commands:
            dual_cmd = dual_role_commands[group_name]
            dual_cname = dual_cmd['cname']
            required_count = sum(1 for arg in dual_cmd.get('args', []) if not arg.get('optional', False))
            
            impl = f"""/**
 * "{group_name}" - Dual Role Dispatcher
 * Both a command group and a specific command
 */
R_IPI RCmdStatus r_{group_cname}_dispatcher(RCore* core, int argc, const char** argv) {{
    // Check for help commands (ends with ? or ??)
    if (argc > 0 && is_help_command(argv[0])) {{
        if (is_double_question_help(argv[0])) {{
            // Double question mark - show specific command help
            print_{dual_cname}_help();
        }} else {{
            // Single question mark - show dual help
            print_{group_name}_dual_help();
        }}
        return R_CMD_STATUS_OK;
    }}

    // Check if we have sufficient arguments for the specific command
    if (validate_arguments(core, argc, argv, {required_count}, "{group_name}", NULL, NULL)) {{
        // Sufficient arguments - call the specific command handler
        return r_{dual_cname}_handler(core, argc, argv);
    }} else {{
        // Insufficient arguments - show help for the specific command
        print_{dual_cname}_help();
        return R_CMD_STATUS_WRONG_ARGS;
    }}
}}
"""
        else:
            impl = f"""/**
 * "{group_name}" - Group Dispatcher
 * Command group dispatcher
 */
R_IPI RCmdStatus r_{group_cname}_dispatcher(RCore* core, int argc, const char** argv) {{
    (void)core;  // Mark unused parameter
    
    // Check if this is a help command (ends with ? or ??)
    if (argc > 0 && is_help_command(argv[0])) {{
        print_{group_cname}_group_help();
        return R_CMD_STATUS_OK;
    }}

    // This is a command group - just show group help
    print_{group_cname}_group_help();
    return R_CMD_STATUS_OK;
}}
"""
        implementations.append(impl)
    
    return '\n'.join(implementations)

def generate_global_dispatcher(commands, command_groups, dual_role_commands):
    """Generate the global command dispatcher"""
    
    # Generate help command routing
    help_routing = []
    
    # Handle dual-role commands first (they need special handling)
    for group_name in dual_role_commands:
        help_routing.append(f"""    if (strcmp(base_cmd, "{group_name}") == 0) {{
        if (is_double_question_help(argv[0])) {{
            print_{dual_role_commands[group_name]['cname']}_help();
        }} else {{
            print_{group_name}_dual_help();
        }}
        free(argv_buf[0]);
        return R_CMD_STATUS_OK;
    }}""")
    
    # Handle other group commands
    for group_name in command_groups:
        if group_name not in dual_role_commands:
            group_cname = camel_to_snake(group_name)
            help_routing.append(f"""    if (strcmp(base_cmd, "{group_name}") == 0) {{
        print_{group_cname}_group_help();
        free(argv_buf[0]);
        return R_CMD_STATUS_OK;
    }}""")
    
    # Handle individual commands (including subcommands)
    for cmd in commands:
        cmd_name = cmd.get('name', '')
        cname = cmd.get('cname', '')
        
        if not cname or cmd_name in dual_role_commands or cmd_name in command_groups:
            continue
            
        help_routing.append(f"""    if (strcmp(base_cmd, "{cmd_name}") == 0) {{
        print_{cname}_help();
        free(argv_buf[0]);
        return R_CMD_STATUS_OK;
    }}""")
    
    # Generate command routing
    command_routing = []
    processed = set()
    
    # Individual commands (not groups)
    for cmd in commands:
        if 'cname' not in cmd:
            continue
            
        cmd_name = cmd['name']
        # Skip if this is a group command or already processed, UNLESS it's a dual-role command
        if (cmd_name in command_groups and cmd_name not in dual_role_commands) or cmd_name in processed:
            continue
        processed.add(cmd_name)
        
        cname = cmd['cname']
        command_routing.append(f"""    if (strcmp(argv[0], "{cmd_name}") == 0) {{
        RCmdStatus status = r_{cname}_dispatcher(core, argc, argv);
        free(argv_buf[0]);
        return status;
    }}""")
    
    # Group commands
    for group_name in command_groups:
        if group_name in processed:
            continue
        processed.add(group_name)
        
        group_cname = camel_to_snake(group_name)
        command_routing.append(f"""    if (strcmp(argv[0], "{group_name}") == 0) {{
        RCmdStatus status = r_{group_cname}_dispatcher(core, argc, argv);
        free(argv_buf[0]);
        return status;
    }}""")
    
    return '\n'.join(help_routing), '\n'.join(command_routing)

def generate_source_file(commands, command_groups, dual_role_commands):
    """Generate CmdDesc.c"""
    current_date = time.strftime('%d %B %Y')
    
    help_implementations = generate_help_implementations(commands, command_groups, dual_role_commands)
    dispatcher_implementations = generate_dispatchers(commands, command_groups, dual_role_commands)
    help_routing, command_routing = generate_global_dispatcher(commands, command_groups, dual_role_commands)
    
    source_content = f"""/**
 * @file : CmdDesc.c
 * @date : {current_date}
 * @author : Generated from YAML command descriptions
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#include "CmdDesc.h"
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* radare */
#include <r_anal.h>
#include <r_cmd.h>
#include <r_cons.h>
#include <r_list.h>
#include <r_util/r_assert.h>
#include <r_util/r_file.h>
#include <r_util/r_num.h>
#include <r_util/r_table.h>
#include <r_vector.h>

/* local includes */
#include <Plugin.h>

#define MAX_ARGS 32

/**
 * Split a command string into argc/argv format
 */
static int split_command_into_args(const char* command, char* argv_buf[], int max_args) {{
    if (!command || !argv_buf || max_args < 1) {{
        return 0;
    }}
    
    int argc = 0;
    char* cmd_copy = strdup(command);
    if (!cmd_copy) {{
        return 0;
    }}
    
    char* token = strtok(cmd_copy, " ");
    while (token && argc < max_args) {{
        argv_buf[argc++] = token;
        token = strtok(NULL, " ");
    }}
    
    return argc;
}}

/**
 * Check if a command is a help request
 */
static bool is_help_command(const char* cmd) {{
    return cmd && strchr(cmd, '?') != NULL;
}}

/**
 * Check if a command has double question marks
 */
static bool is_double_question_help(const char* cmd) {{
    if (!cmd) return false;
    char* first_q = strchr(cmd, '?');
    return first_q && *(first_q + 1) == '?';
}}

/**
 * Extract base command from help command
 */
static char* extract_base_command(const char* cmd) {{
    if (!cmd) return NULL;
    
    static char base_cmd[32];
    strncpy(base_cmd, cmd, sizeof(base_cmd) - 1);
    base_cmd[sizeof(base_cmd) - 1] = '\\0';
    
    char* question_mark = strchr(base_cmd, '?');
    if (question_mark) {{
        *question_mark = '\\0';
    }}
    
    return base_cmd;
}}

/**
 * Validate command arguments
 */
static bool validate_arguments(RCore* core, int argc, const char** argv, int required_count, 
                              const char* cmd_name, const char* arg_types[], bool optional[]) {{
    (void)core;     // Mark unused parameters
    (void)cmd_name;
    (void)arg_types;
    (void)optional;
    
    if (argc <= 0 || !argv || !argv[0]) {{
        return false;
    }}
    
    return argc - 1 >= required_count;
}}

/**
 * General help handler - for backward compatibility
 */
R_API RCmdStatus r_show_help_handler(RCore* core, int argc, const char** argv) {{
    (void)core; (void)argc; (void)argv;
    print_root_help();
    return R_CMD_STATUS_OK;
}}

/**
 * Global command dispatcher - entry point for all commands
 */
R_API RCmdStatus reai_global_command_dispatcher(RCore* core, const char* command) {{
    if (!core || !command || !*command) {{
        DISPLAY_ERROR("Invalid command or core pointer");
        return R_CMD_STATUS_INVALID;
    }}
    
    char* argv_buf[MAX_ARGS] = {{0}};
    int argc = split_command_into_args(command, argv_buf, MAX_ARGS);
    
    if (argc == 0) {{
        DISPLAY_ERROR("Empty command");
        return R_CMD_STATUS_INVALID;
    }}
    
    const char* argv[MAX_ARGS];
    for (int i = 0; i < argc; i++) {{
        argv[i] = argv_buf[i];
    }}
    
    // Check for root help
    if (strcmp(argv[0], "?") == 0 || strcmp(argv[0], "help") == 0 || strcmp(argv[0], "RE?") == 0) {{
        print_root_help();
        free(argv_buf[0]);
        return R_CMD_STATUS_OK;
    }}
    
    // Handle help commands with question marks
    if (is_help_command(argv[0])) {{
        char* base_cmd = extract_base_command(argv[0]);
        
{help_routing}
        
        // If no specific help found, show root help
        print_root_help();
        free(argv_buf[0]);
        return R_CMD_STATUS_OK;
    }}
    
    // Route to appropriate dispatcher
{command_routing}
    
    // Command not found
    RCmdStatus status = r_show_help_handler(core, argc, argv);
    free(argv_buf[0]);
    return status;
}}

/* Help function implementations */
{help_implementations}

/* Dispatcher implementations */
{dispatcher_implementations}
"""
    
    return source_content

def main():
    """Main function"""
    commands, command_groups, dual_role_commands = load_commands()
    
    # Generate files
    header_content = generate_header_file(commands, command_groups, dual_role_commands)
    source_content = generate_source_file(commands, command_groups, dual_role_commands)
    
    # Write files
    with open(os.path.join('Source', 'Radare', 'CmdDesc.h'), 'w') as f:
        f.write(header_content)
    print("Generated Source/Radare/CmdDesc.h")
    
    with open(os.path.join('Source', 'Radare', 'CmdDesc.c'), 'w') as f:
        f.write(source_content)
    print("Generated Source/Radare/CmdDesc.c")

if __name__ == "__main__":
    main() 