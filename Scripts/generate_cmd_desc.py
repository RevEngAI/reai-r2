#!/usr/bin/env python3
# Generate CmdDesc.h and CmdDesc.c from YAML command descriptions
# Copyright (c) 2024 RevEngAI. All Rights Reserved.

import os
import sys
import yaml
import glob
import time
from datetime import datetime
from typing import Tuple, Dict, List, Any

def process_command_group(
    data: Dict[str, Any],
    simple_commands: List[Dict[str, Any]],
    command_groups: Dict[str, Dict[str, Any]]
) -> None:
    """
    Recursively processes a nested command structure and separates it into simple commands
    and command groups.

    Parameters:
    ----------
    data : dict
        A dictionary representing either a command group or a command.
        Must contain a 'group' key if it is a group.

    simple_commands : list
        A list to which simple command dictionaries (with a 'name' key) will be appended.

    command_groups : dict
        A dictionary where command group names are mapped to their summary and contained commands.

    Raises:
    ------
    ValueError:
        If a command group contains unexpected keys such as 'name', 'args', or 'cname'.
        Or if a dictionary without 'group' is passed at the top level.

    Example:
    -------
    simple_cmds = []
    cmd_groups = {}
    process_command_group(parsed_yaml_data, simple_cmds, cmd_groups)
    """

    if 'group' in data:
        # Validation: command group should not contain command fields
        invalid_keys = {'name', 'args', 'cname'}
        if any(key in data for key in invalid_keys):
            raise ValueError(
                f"Invalid command group declaration '{data['group']}': "
                f"contains unrequired fields {invalid_keys & data.keys()}"
            )

        # Extract group details
        group_name = data['group']
        group_summary = data.get('summary', '')
        group_commands = data.get('commands', [])

        # Store in command_groups dictionary
        if group_name in command_groups:
            # Merge with existing group
            existing_group = command_groups[group_name]
            
            # Use the new summary if it's more descriptive, otherwise keep existing
            if group_summary and len(group_summary) > len(existing_group.get('summary', '')):
                existing_group['summary'] = group_summary
            
            # Merge commands (extend the existing commands list)
            existing_commands = existing_group.get('commands', [])
            existing_commands.extend(group_commands)
            existing_group['commands'] = existing_commands
        else:
            # Create new group
            command_groups[group_name] = {
                'summary': group_summary,
                'commands': group_commands
            }

        # Recursively process each command in the group
        for cmd in group_commands:
            # Optional: annotate each command with its parent group for traceability
            cmd['parent'] = group_name

            if 'group' in cmd:
                process_command_group(cmd, simple_commands, command_groups)
            elif 'name' in cmd:
                if 'commands' in cmd:
                    raise ValueError(
                        f"Invalid command {cmd['name']} with 'commands' field inside it's declaration"
                    )
                simple_commands.append(cmd)
            else:
                raise ValueError(
                    f"Malformed command entry in group '{group_name}': expected either 'group' or 'name'"
                )
    else:
        raise ValueError(
            "Expected a command group at the top level. Found an entry without a 'group' key."
        )

def load_commands() -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """
    Load command definitions from YAML files and process them into:
    - Simple commands
    - Command groups
    - Dual-role commands (groups that also contain a command with the same name)

    Returns:
    -------
    Tuple containing:
    - simple_commands: List of individual command dictionaries
    - command_groups: Dictionary mapping group names to group metadata and commands
    - dual_role_commands: Dictionary of groups that also have a command of the same name

    Raises:
    ------
    ValueError:
        If any YAML file does not conform to the expected structure.
    """
    simple_commands = []
    command_groups = {}
    dual_role_commands = {}

    # Load all YAML files in the expected directory
    yaml_files = glob.glob(os.path.join('Source', 'Radare', 'CmdDesc', '*.yaml'))

    for yaml_file in yaml_files:
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)

        # Basic structural validation
        if not data or 'group' not in data or 'commands' not in data:
            raise ValueError(f"Invalid structure in {yaml_file}: expected a top-level command group")

        process_command_group(data, simple_commands, command_groups)

    # Detect nested groups and dual-role commands
    all_command_names = [cmd.get('name') for cmd in simple_commands if cmd.get('name')]

    for group_name, group_data in command_groups.items():
        group_cmds = group_data.get('commands', [])

        # Detect dual-role: if a command in the group has the same name as the group
        for cmd in group_cmds:
            if cmd.get('name') == group_name:
                dual_role_commands[group_name] = {
                    'group': group_data,
                    'command': cmd
                }

    return simple_commands, command_groups, dual_role_commands

def camel_to_snake(name: str) -> str:
    """Convert camelCase or PascalCase to snake_case."""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def generate_header_file(
    simple_commands: List[Dict[str, Any]],
    command_groups: Dict[str, Any],
    dual_role_commands: Dict[str, Dict[str, Any]]
) -> str:
    """
    Generate the contents of the CmdDesc.h header file based on parsed command definitions.

    Parameters:
    ----------
    simple_commands : list of dict
        List of individual commands (with 'name' and optional 'cname').

    command_groups : dict
        Mapping of command group names to group metadata including summary and commands.

    dual_role_commands : dict
        Mapping of group names to their dual role command (a group and command with same name).

    Returns:
    -------
    str
        The contents of the generated header file as a string.
    """
    current_date = time.strftime('%d %B %Y')

    # Handler declarations
    handler_declarations = []
    for cmd in simple_commands:
        if 'cname' in cmd:
            cmd_name = cmd['name']
            if cmd_name not in command_groups or cmd_name in dual_role_commands:
                handler_declarations.append(
                    f"R_API RCmdStatus r_{cmd['cname']}_handler(RCore* core, int argc, const char** argv);"
                )

    # Dispatcher declarations
    dispatcher_declarations = []
    processed = set()

    for cmd in simple_commands:
        if 'cname' in cmd:
            cmd_name = cmd['name']
            if (cmd_name not in command_groups or cmd_name in dual_role_commands) and cmd_name not in processed:
                dispatcher_declarations.append(
                    f"R_IPI RCmdStatus r_{cmd['cname']}_dispatcher(RCore* core, int argc, const char** argv);"
                )
                processed.add(cmd_name)

    for group_name in command_groups:
        if group_name not in processed:
            group_cname = camel_to_snake(group_name)
            dispatcher_declarations.append(
                f"R_IPI RCmdStatus r_{group_cname}_dispatcher(RCore* core, int argc, const char** argv);"
            )
            processed.add(group_name)

    # Help function declarations
    help_declarations = ["void print_root_help(void);"]

    for cmd in simple_commands:
        if 'cname' in cmd:
            help_declarations.append(f"void print_{cmd['cname']}_help(void);")

    for group_name in command_groups:
        group_cname = camel_to_snake(group_name)
        help_declarations.append(f"void print_{group_cname}_group_help(void);")

        if group_name in dual_role_commands:
            help_declarations.append(f"void print_{group_cname}_dual_help(void);")

    # Construct header content
    header_content = f"""/**
 * @file : CmdDesc.h
 * @date : {current_date}
 * @author : Generated from YAML command descriptions
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 */

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
 
def generate_help_implementations(
    simple_commands: List[Dict[str, Any]],
    command_groups: Dict[str, Any],
    dual_role_commands: Dict[str, Dict[str, Any]]
) -> str:
    """
    Generate the C help function implementations for commands and command groups.

    Parameters:
    ----------
    simple_commands : list of dict
        All simple command definitions.

    command_groups : dict
        Mapping of command group names to their metadata and nested commands.

    dual_role_commands : dict
        Mapping of group names to a dict containing both group and its command.

    Returns:
    -------
    str
        The generated C function implementations as a string.
    """
    implementations = []

    # Root Help
    implementations.append("""/**
 * Print root level help for all commands
 */
void print_root_help(void) {
    r_cons_println("RevEngAI Radare2 Plugin - Command Help");
    r_cons_println("=======================================");""")

    for group_name in command_groups:
        group_info = command_groups[group_name]
        # Use the group's own summary first, then fall back to generic description
        group_summary = group_info.get('summary', f"Commands for {group_name} operations")

        # Try to extract a summary from an individual command (if present)
        for cmd in group_info.get("commands", []):
            if cmd.get("name") == group_name and 'parent' not in cmd:
                group_summary = cmd.get("summary", group_summary)
                break

        group_summary_escaped = group_summary.replace('"', '\\"')
        implementations[-1] += f'\n    r_cons_println("{group_name:<8} - {group_summary_escaped}");'

    implementations[-1] += '''
    r_cons_println("");
    r_cons_println("Use <command>?  to get help for a group");
    r_cons_println("Use <command>\\?\\? to get help for a specific command");
}
'''

    # Command Help Functions
    processed_help_functions = set()
    for cmd in simple_commands:
        cname = camel_to_snake(cmd.get('cname'))
        cmd_name = cmd.get('name')

        # if it's already processed skip
        if not cname or cname in processed_help_functions:
            continue

        processed_help_functions.add(cname)
        summary = cmd.get('summary', '').replace('"', '\\"')
        args = cmd.get('args', [])

        usage = cmd_name
        for arg in args:
            arg_name = arg['name']
            usage += f" [{'<' + arg_name + '>' if not arg.get('optional') else '[<' + arg_name + '>]'}]"

        usage_line = f'{usage} # {summary}'

        help_impl = f"""/**
 * Print help for {cmd_name} command
 */
void print_{cname}_help(void) {{
    r_cons_println("{usage_line}");"""

        # Process all detail sections
        for detail in cmd.get('details', []):
            detail_name = detail.get('name')
            if detail_name == 'Notes':
                help_impl += '\n    r_cons_println("\\nNotes:");'
                for entry in detail.get('entries', []):
                    text = entry.get('text', '').replace('"', '\\"')
                    help_impl += f'\n    r_cons_println("  {text}");'
            elif detail_name == 'Examples':
                help_impl += '\n    r_cons_println("\\nExamples:");'
                for entry in detail.get('entries', []):
                    text = entry.get('text', '').replace('"', '\\"')
                    comment = entry.get('comment', '').replace('"', '\\"')
                    help_impl += f'\n    r_cons_println("{text}  # {comment}");'
            elif detail_name == 'Usage':
                help_impl += '\n    r_cons_println("\\nUsage:");'
                for entry in detail.get('entries', []):
                    text = entry.get('text', '').replace('"', '\\"')
                    comment = entry.get('comment', '').replace('"', '\\"')
                    help_impl += f'\n    r_cons_println("| {text:<15} # {comment}");'
            elif detail_name == 'Controls':
                help_impl += '\n    r_cons_println("\\nControls:");'
                for entry in detail.get('entries', []):
                    text = entry.get('text', '').replace('"', '\\"')
                    comment = entry.get('comment', '').replace('"', '\\"')
                    help_impl += f'\n    r_cons_println("| {text:<6} # {comment}");'

        help_impl += '\n}\n'
        implementations.append(help_impl)

    # Group Help Functions
    for group_name, group_data in command_groups.items():
        group_cname = camel_to_snake(group_name)
        group_commands = group_data.get('commands', [])

        help_impl = f"""/**
 * Print help for {group_name} command group
 */
void print_{group_cname}_group_help(void) {{
    r_cons_println("{group_name} Command Group");
    r_cons_println("{'=' * (len(group_name) + 14)}");"""

        # Filter out subcommands of nested groups
        nested_prefixes = [
            name for name in command_groups if name != group_name and name.startswith(group_name)
        ]

        for cmd in sorted(group_commands, key=lambda x: x.get('name', '')):
            cmd_name = cmd.get('name', cmd.get('group', ''))
            summary = cmd.get('summary', '').replace('"', '\\"')
            if not any(cmd_name.startswith(prefix) and len(cmd_name) > len(prefix) for prefix in nested_prefixes):
                help_impl += f'\n    r_cons_println("{cmd_name:<12} - {summary}");'

        help_impl += '''
    r_cons_println("");
    r_cons_println("Use <command>? to get detailed help for a specific command");
}
'''
        implementations.append(help_impl)

        # Dual Help Function
        if group_name in dual_role_commands:
            dual_cmd = dual_role_commands[group_name]['command']
            dual_cname = dual_cmd.get('cname')
            dual_summary = dual_cmd.get('summary', '').replace('"', '\\"')
            separator = '=' * (len("Available commands in " + group_name + " group:"))

            dual_help = f"""/**
 * Print dual help for {group_name} (both group and command)
 */
void print_{group_cname}_dual_help(void) {{
    r_cons_println("{group_name} - Dual Role Command");
    r_cons_println("{'=' * (len(group_name) + 19)}");
    r_cons_println("This command has two roles:");
    r_cons_println("");
    r_cons_println("1. As a command group:");
    r_cons_println("   Contains subcommands for {group_name} operations");
    r_cons_println("   Use '{group_name}?' to see group help");
    r_cons_println("");
    r_cons_println("2. As a specific command:");
    r_cons_println("   {dual_summary}");
    r_cons_println("   Use '{group_name}\\?\\?' to see command-specific help");
    r_cons_println("");
    r_cons_println("Available commands in {group_name} group:");
    r_cons_println("{separator}");"""

            for cmd in sorted(group_commands, key=lambda x: x.get('name', '')):
                cmd_name = cmd.get('name', '')
                summary = cmd.get('summary', '').replace('"', '\\"')
                dual_help += f'\n    r_cons_println("{cmd_name:<12} - {summary}");'

            dual_help += """
    r_cons_println("");
    r_cons_println("Use <command>? to get detailed help for a specific command");
}
"""
            implementations.append(dual_help)

    return '\n'.join(implementations)

def generate_dispatchers(
    simple_commands: List[Dict[str, Any]],
    command_groups: Dict[str, Any],
    dual_role_commands: Dict[str, Dict[str, Any]]
) -> str:
    """
    Generate dispatcher C function implementations.

    Parameters:
    ----------
    simple_commands : list of dict
        List of standalone command definitions.

    command_groups : dict
        Mapping of group names to group metadata and their subcommands.

    dual_role_commands : dict
        Dictionary of command groups that also act as individual commands.

    Returns:
    -------
    str
        The generated dispatcher implementations as a single C source string.
    """
    implementations = []
    processed = set()

    # Dispatchers for individual commands
    for cmd in simple_commands:
        cname = cmd.get('cname')
        cmd_name = cmd.get('name')
        if not cname or cmd_name in processed:
            continue

        # Skip if it's only a group (unless dual-role)
        if cmd_name in command_groups and cmd_name not in dual_role_commands:
            continue

        processed.add(cmd_name)
        summary = cmd.get('summary', '').replace('"', '\\"')
        required_count = sum(1 for arg in cmd.get('args', []) if not arg.get('optional'))

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

    // Validate command arguments
    if (!validate_arguments(core, argc, argv, {required_count}, "{cmd_name}", NULL, NULL)) {{
        print_{cname}_help();
        return R_CMD_STATUS_WRONG_ARGS;
    }}

    return r_{cname}_handler(core, argc, argv);
}}
"""
        implementations.append(impl)

    # Dispatchers for command groups (including dual-role)
    for group_name, group_data in command_groups.items():
        if group_name in processed:
            continue
        processed.add(group_name)

        group_cname = camel_to_snake(group_name)

        if group_name in dual_role_commands:
            dual_cmd = dual_role_commands[group_name]['command']
            dual_cname = dual_cmd['cname']
            required_count = sum(1 for arg in dual_cmd.get('args', []) if not arg.get('optional'))

            impl = f"""/**
 * "{group_name}" - Dual Role Dispatcher
 * Acts as both a command and a group
 */
R_IPI RCmdStatus r_{group_cname}_dispatcher(RCore* core, int argc, const char** argv) {{
    // Help behavior
    if (argc > 0 && is_help_command(argv[0])) {{
        if (is_double_question_help(argv[0])) {{
            print_{dual_cname}_help();
        }} else {{
            print_{group_cname}_dual_help();
        }}
        return R_CMD_STATUS_OK;
    }}

    // Check for enough args to treat as individual command
    if (validate_arguments(core, argc, argv, {required_count}, "{group_name}", NULL, NULL)) {{
        return r_{dual_cname}_handler(core, argc, argv);
    }} else {{
        print_{dual_cname}_help();
        return R_CMD_STATUS_WRONG_ARGS;
    }}
}}
"""
        else:
            impl = f"""/**
 * "{group_name}" - Group Dispatcher
 * Dispatches help for command group
 */
R_IPI RCmdStatus r_{group_cname}_dispatcher(RCore* core, int argc, const char** argv) {{
    (void)core;

    if (argc > 0 && is_help_command(argv[0])) {{
        print_{group_cname}_group_help();
        return R_CMD_STATUS_OK;
    }}

    print_{group_cname}_group_help();
    return R_CMD_STATUS_OK;
}}
"""
        implementations.append(impl)

    return '\n'.join(implementations)

def generate_global_dispatcher(
    simple_commands: List[Dict[str, Any]],
    command_groups: Dict[str, Any],
    dual_role_commands: Dict[str, Dict[str, Any]]
) -> Tuple[str, str]:
    """
    Generate help routing and command routing C code for the global dispatcher.

    Returns:
    -------
    (str, str)
        help_routing_code, command_routing_code
    """
    help_routing = []
    command_routing = []
    processed = set()

    # --- Help Routing ---
    for group_name, dual_data in dual_role_commands.items():
        cname = camel_to_snake(dual_data['command']['cname'])
        help_routing.append(f"""    if (strcmp(base_cmd, "{group_name}") == 0) {{
        if (is_double_question_help(argv[0])) {{
            print_{cname}_help();
        }} else {{
            print_{camel_to_snake(group_name)}_dual_help();
        }}
        free(cmd_copy);
        return R_CMD_STATUS_OK;
    }}""")

    # Dispatchers for command groups
    for group_name in command_groups:
        if group_name not in dual_role_commands:
            group_cname = camel_to_snake(group_name)
            help_routing.append(f"""    if (strcmp(base_cmd, "{group_name}") == 0) {{
        print_{group_cname}_group_help();
        free(cmd_copy);
        return R_CMD_STATUS_OK;
    }}""")

    # Fnally dispatchers for all simple commands
    for cmd in simple_commands:
        cmd_name = cmd.get('name')
        cname = cmd.get('cname')
        if not cname or cmd_name in dual_role_commands or cmd_name in command_groups:
            continue
        help_routing.append(f"""    if (strcmp(base_cmd, "{cmd_name}") == 0) {{
        print_{cname}_help();
        free(cmd_copy);
        return R_CMD_STATUS_OK;
    }}""")

    # --- Command Routing ---
    for cmd in simple_commands:
        cmd_name = cmd.get('name')
        cname = cmd.get('cname')
        if not cname or cmd_name in processed:
            continue

        # Skip group-only commands unless dual-role
        if cmd_name in command_groups and cmd_name not in dual_role_commands:
            continue

        processed.add(cmd_name)
        command_routing.append(f"""    if (strcmp(argv[0], "{cmd_name}") == 0) {{
        RCmdStatus status = r_{cname}_dispatcher(core, argc, argv);
        free(cmd_copy);
        return status;
    }}""")

    for group_name in command_groups:
        if group_name in processed:
            continue
        processed.add(group_name)
        group_cname = camel_to_snake(group_name)
        command_routing.append(f"""    if (strcmp(argv[0], "{group_name}") == 0) {{
        RCmdStatus status = r_{group_cname}_dispatcher(core, argc, argv);
        free(cmd_copy);
        return status;
    }}""")

    return '\n'.join(help_routing), '\n'.join(command_routing)

def generate_source_file(simple_commands, command_groups, dual_role_commands):
    """Generate CmdDesc.c"""
    current_date = time.strftime('%d %B %Y')

    # Generate code blocks
    help_implementations = generate_help_implementations(simple_commands, command_groups, dual_role_commands)
    dispatcher_implementations = generate_dispatchers(simple_commands, command_groups, dual_role_commands)
    help_routing, command_routing = generate_global_dispatcher(simple_commands, command_groups, dual_role_commands)

    # Compose final C source file
    source_content = f"""/**
 * @file : CmdDesc.c
 * @date : {current_date}
 * @author : Generated from YAML command descriptions
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 */

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
 * Note: Caller must free the returned cmd_copy pointer
 */
static int split_command_into_args(const char* command, char* argv_buf[], int max_args, char** cmd_copy_out) {{
    if (!command || !argv_buf || max_args < 1 || !cmd_copy_out) {{
        return 0;
    }}

    int argc = 0;
    char* cmd_copy = strdup(command);
    if (!cmd_copy) {{
        return 0;
    }}

    *cmd_copy_out = cmd_copy;  // Return the allocated pointer for later freeing

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
    (void)core;
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
    char* cmd_copy = NULL;
    int argc = split_command_into_args(command, argv_buf, MAX_ARGS, &cmd_copy);

    if (argc == 0) {{
        DISPLAY_ERROR("Empty command");
        if (cmd_copy) free(cmd_copy);
        return R_CMD_STATUS_INVALID;
    }}

    const char* argv[MAX_ARGS];
    for (int i = 0; i < argc; i++) {{
        argv[i] = argv_buf[i];
    }}

    // Check for root help
    if (strcmp(argv[0], "RE?") == 0) {{
        print_root_help();
        free(cmd_copy);
        return R_CMD_STATUS_OK;
    }}

    // Handle help commands with question marks
    if (is_help_command(argv[0])) {{
        char* base_cmd = extract_base_command(argv[0]);

{help_routing}

        // Fallback if command not found
        print_root_help();
        free(cmd_copy);
        return R_CMD_STATUS_OK;
    }}

    // Route to appropriate dispatcher
{command_routing}

    // Unknown command
    RCmdStatus status = r_show_help_handler(core, argc, argv);
    free(cmd_copy);
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
    simple_commands, command_groups, dual_role_commands = load_commands()

    # Generate files
    header_content = generate_header_file(simple_commands, command_groups, dual_role_commands)
    source_content = generate_source_file(simple_commands, command_groups, dual_role_commands)

    # Write files
    with open(os.path.join('Source', 'Radare', 'CmdDesc.h'), 'w') as f:
        f.write(header_content)
    print("Generated Source/Radare/CmdDesc.h")

    with open(os.path.join('Source', 'Radare', 'CmdDesc.c'), 'w') as f:
        f.write(source_content)
    print("Generated Source/Radare/CmdDesc.c")

if __name__ == "__main__":
    main()
