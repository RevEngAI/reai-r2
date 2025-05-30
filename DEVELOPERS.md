# RevEngAI Radare2 Plugin - Developer Documentation

This repository has been completely rewritten to use a modern, automated command generation system. This guide covers everything developers need to know to work with this codebase effectively.

## 🏗️ Architecture Overview

The plugin architecture consists of several key components:

### Core Components
- **Command System**: YAML-driven command definitions with automatic code generation
- **Plugin Core**: Core radare2 plugin integration (`Source/Radare/Radare.c`)
- **Command Handlers**: Business logic implementations (`Source/Radare/CmdHandlers.c`)
- **Generated Code**: Auto-generated dispatchers and help system (`CmdDesc.h`, `CmdDesc.c`)

### Dependencies
- **creait**: RevEngAI C API client library
- **Radare2**: Reverse engineering framework (version 5.9.8+)
- **Python 3**: Required for command generation
- **PyYAML**: Python package for YAML parsing

## 🎯 Command Generation System

### How It Works

The plugin uses a sophisticated YAML-to-C code generation system:

1. **YAML Definitions** (`Source/Radare/CmdDesc/*.yaml`) define all commands
2. **Python Generator** (`Scripts/generate_cmd_desc.py`) processes YAML files
3. **Generated Code** (`CmdDesc.h`, `CmdDesc.c`) provides dispatchers and help
4. **CMake Integration** automatically triggers regeneration during build

### Command Types

The system supports multiple command types:

#### 1. Individual Commands
```yaml
- name: REi
  cname: plugin_initialize
  summary: Initialize plugin config with API key
  args:
    - name: api_key
      type: ARG_TYPE_STRING
      optional: false
```

#### 2. Command Groups
Commands that contain other commands are automatically detected as groups:
```yaml
group: REa
commands:
  - name: REa      # Dual-role: both group and command
  - name: REap     # Subcommand
  - name: REar     # Subcommand
```

#### 3. Nested Groups
Commands like `REca` that have subcommands (`REcat`, `REcam`, etc.) are automatically detected as nested groups.

### YAML File Structure

Each YAML file defines a command group:

```yaml
group: GroupName
commands:
  - name: CommandName
    cname: handler_function_name
    summary: Brief description
    args:
      - name: argument_name
        type: ARG_TYPE_STRING|ARG_TYPE_NUMBER
        optional: true|false
        default: value  # optional
    details:
      - name: Examples|Notes
        entries:
          - text: "Example command"
            comment: "What this does"
```

### Generated Code Structure

The generator creates:

- **Dispatchers**: Route commands and validate arguments
- **Help Functions**: Generate contextual help output
- **Global Router**: Main entry point for all commands
- **Declarations**: Function signatures in header file

## 🔧 Adding New Commands

### Step 1: Define Command in YAML

Choose the appropriate YAML file in `Source/Radare/CmdDesc/`:
- `index.yaml` - Root-level commands (REi, REm, REh, etc.)
- `analysis.yaml` - Analysis commands (REa group)
- `function.yaml` - Function commands (REf group)
- `binary.yaml` - Binary commands (REb group)
- `collection.yaml` - Collection commands (REc group)

Add your command definition:

```yaml
- name: REnew
  cname: my_new_command
  summary: Description of what this command does
  args:
    - name: required_param
      type: ARG_TYPE_STRING
      optional: false
    - name: optional_param
      type: ARG_TYPE_NUMBER
      optional: true
  details:
    - name: Examples
      entries:
        - text: REnew "hello" 42
          comment: Example with both parameters
        - text: REnew "hello"
          comment: Example with optional param omitted
```

### Step 2: Implement Handler Function

Add your handler in `Source/Radare/CmdHandlers.c`:

```c
/**
 * "REnew" - Handler implementation
 */
R_IPI RCmdStatus r_my_new_command_handler(RCore* core, int argc, const char** argv) {
    // Extract arguments using helper macros
    Str required_param = StrInit();
    u64 optional_param = 0;
    
    // Use STR_ARG and NUM_ARG macros for argument extraction
    if (!STR_ARG(required_param, 1)) {
        DISPLAY_ERROR("Required parameter missing");
        StrDeinit(&required_param);
        return R_CMD_STATUS_WRONG_ARGS;
    }
    
    // Optional parameter (check if provided)
    NUM_ARG(optional_param, 2);
    
    // Your command logic here
    r_cons_printf("Processing: %s with value: %llu\n", 
                  required_param.data, optional_param);
    
    // Cleanup
    StrDeinit(&required_param);
    
    return R_CMD_STATUS_OK;
}
```

### Step 3: Build and Test

The build system automatically generates the dispatcher and help code:

```bash
# The command will be automatically available after build
ninja -C build
```

## 🔨 Build System

### CMake Integration

The build system uses custom commands to generate code:

```cmake
# Auto-generation happens during build
add_custom_command(
    OUTPUT CmdDesc.h CmdDesc.c
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Scripts/generate_cmd_desc.py
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating command descriptors from YAML"
)
```

### When Code is Generated

Code generation occurs:
1. **During CMake Configure**: If output files don't exist
2. **During Build**: If YAML files are newer than generated files
3. **Manual Trigger**: Running the generator script directly

### Manual Generation

```bash
# From project root
python Scripts/generate_cmd_desc.py
```

## 🏃‍♂️ Development Workflow

### Quick Setup (Unix/macOS)

```bash
# Clone and build everything
git clone https://github.com/revengai/reai-r2
cd reai-r2
./Scripts/Build.sh
```

### Development Cycle

1. **Modify YAML files** to add/change commands
2. **Implement handlers** in `CmdHandlers.c`
3. **Build project** - code generation happens automatically
4. **Test in radare2** - plugin loads automatically

```bash
# Development build
mkdir -p build
cd build
cmake ..
ninja

# Test your changes
r2 /bin/ls
[0x00001000]> REyourcommand
```

### Windows Development

Use the PowerShell scripts:

```powershell
# Full build and setup
.\Scripts\Build.ps1

# Development environment setup
$InstallPath = "~\.local\RevEngAI\Radare2\Install"
$env:Path = $env:Path + ";$InstallPath;$InstallPath\bin;$InstallPath\lib"

# Build with changes
cmake -A x64 -B "Build" -G "Visual Studio 17 2022" -D CMAKE_PREFIX_PATH="$InstallPath"
cmake --build Build --config Release
```

## 🧪 Testing

### Manual Testing

```bash
# Load radare2 with a binary
r2 /bin/ls

# Test root help
[0x00001000]> RE?

# Test group help
[0x00001000]> REa?

# Test specific command help
[0x00001000]> REi?

# Test dual-role command help
[0x00001000]> REa?     # Shows dual help + command list
[0x00001000]> REa??    # Shows specific REa command help

# Test command execution
[0x00001000]> REi your-api-key-here
[0x00001000]> REm
[0x00001000]> REh
```

### Automated Testing

The system validates:
- **Argument Count**: Correct number of required/optional args
- **Help Triggers**: `?` and `??` work correctly
- **Command Routing**: Commands route to correct handlers
- **Build Integration**: Code generation works in CI/CD

## 📝 Code Style & Standards

### Handler Function Naming
- Pattern: `r_{cname}_handler`
- Example: `r_plugin_initialize_handler`

### Argument Handling
```c
// Use provided macros for consistency
STR_ARG(variable, index)   // String arguments
NUM_ARG(variable, index)   // Numeric arguments
ZSTR_ARG(variable, index)  // C string arguments

// Example
Str filename = StrInit();
u64 address = 0;
if (STR_ARG(filename, 1) && NUM_ARG(address, 2)) {
    // Process arguments
}
StrDeinit(&filename);
```

### Error Handling
```c
// Use consistent error reporting
if (error_condition) {
    DISPLAY_ERROR("Clear error message");
    return R_CMD_STATUS_ERROR;
}

// For argument errors
if (!sufficient_args) {
    DISPLAY_ERROR("Usage: command <required> [optional]");
    return R_CMD_STATUS_WRONG_ARGS;
}
```

### Memory Management
- Always clean up `Str` objects with `StrDeinit()`
- Use RAII patterns where possible
- Check for allocation failures

## 🐛 Debugging

### Common Issues

1. **Command Not Found**
   - Check YAML syntax
   - Verify cname matches handler function
   - Ensure build regenerated files

2. **Help Not Showing**
   - Verify `?` detection logic
   - Check argument validation

3. **Build Errors**
   - Missing handler implementation
   - Python/PyYAML not available
   - YAML syntax errors

### Debug Tips

```c
// Add debug logging
LOG_INFO("Command called with %d args", argc);
for (int i = 0; i < argc; i++) {
    LOG_INFO("Arg %d: %s", i, argv[i]);
}
```

## 🚀 Advanced Features

### Custom Argument Types
Add new argument types by extending the generator:

```python
# In generate_cmd_desc.py
ARG_TYPE_MAPPINGS = {
    'ARG_TYPE_STRING': 'string',
    'ARG_TYPE_NUMBER': 'number', 
    'ARG_TYPE_ADDRESS': 'address',  # Custom type
}
```

### Complex Command Groups
Create sophisticated command hierarchies:

```yaml
group: REcomplex
commands:
  - name: REcomplex        # Root command
  - name: REcomplexsub     # Creates nested group
  - name: REcomplexsubopt1 # Member of nested group
  - name: REcomplexsubopt2 # Member of nested group
```

### Integration with creait API
Most handlers will use the creait API:

```c
// Common pattern for API commands
Connection* conn = GetConnection();
if (!conn || !Authenticate(conn)) {
    DISPLAY_ERROR("Not connected to RevEngAI");
    return R_CMD_STATUS_ERROR;
}

// Use API functions
Result result = SomeApiCall(conn, parameters);
if (!result.success) {
    DISPLAY_ERROR("API call failed: %s", result.error);
    return R_CMD_STATUS_ERROR;
}
```

## 📚 Additional Resources

- **creait Documentation**: API client library docs
- **Radare2 Plugin Development**: Official r2 plugin docs
- **YAML Specification**: Understanding YAML syntax
- **CMake Documentation**: Build system reference

---

## 🤝 Contributing

When contributing:

1. **Add YAML definitions** for new commands
2. **Implement handlers** with proper error handling
3. **Test thoroughly** with various input combinations
4. **Update documentation** if adding major features
5. **Follow existing patterns** for consistency

The automated code generation ensures consistency and reduces boilerplate, making the codebase maintainable and extensible.
