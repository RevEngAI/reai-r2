# RevEng.AI Radare Plugin

RevEng.AI plugin for Radare.

## Installation

### Docker

Don't want to go through all the manual hassle? We have a dockerfile as well.
Just do :

```bash
git clone https://github.com/revengai/reai-r2 && 
cd reai-r2 && sed -i -e 's/APIKEY/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/g' Dockerfile && 
docker build -t reai-r2 . &&
docker run -v /tmp/userdata:/home/revengai/userdata -it reai-rz
```

This will get you a working installation of the radare plugin in a single command!

- Store the files you want to access into `/tmp/userdata` directory of host,
  and access these files through `~/userdata` inside the docker container.

- To be able to use the plugin in one single command. Make sure to initialize your plugin with
  `REi <api-key>` command. Get your API key from RevEngAI portal.

### Manual

```sh
# Get plugin or download a release
git clone git@github.com:RevEngAI/reai-r2.git && cd reai-r2

# Configure the build. Remove -G Ninja if you prefer GNU Makefiles (requires make)
cmake -B Build -G Ninja

# Build & Install plugin
ninja -C Build && sudo ninja -C Build install
```

### Dependencies

Before running any of the above commands, you must install cmake, make, ninja, meson, gcc/g++ (if required), pkg-config, libcurl (development package), and [radare](https://github.com/radareorg/radare2).

## Basic Usage

Before being able to use anything in the plugin, a config file in the user's home
directory is required. Name of file must be `.creait.toml`

```toml
apikey = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"    # Replace this with your own API key
host = "https://api.reveng.ai"                  # API version and base endpoint
```

### Generating Config File In Plugin

This config file can be generated using the `REi` command after plugin installation.
Without a config, the plugin will keep erroring out for all other commands.

`REi <apikey>`

Execute the above command to automatically create a config file similar to the one above.
You can get the api key in `https://portal.reveng.ai/settings` API Key section. Once
the config file is generated, exit radare using `q` command and then run radare again.

### Command List

After installing radare plugin, you'll see the following commands listed when you execute the
`RE?` command in radare shell.

```sh
Usage: RE<imhua?>   # RevEngAI Plugin Commands
| REi <api_key>=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX # Initialize plugin config.
| REm                     # Get all available models for analysis.
| REh                     # Check connection status with RevEngAI servers.
| REu                     # Upload currently loaded binary to RevEngAI servers.
| REa <prog_name> <cmd_line_args> <ai_model> # Upload and analyse currently loaded binary
| REau[?] <min_confidence>=90 # Auto analyze binary functions using ANN and perform batch rename.
| REap <bin_id>           # Apply already existing RevEng.AI analysis to this binary.
| REd  <fn_name>          # Perform AI Decompilation
| REfl[?]                 # Get & show basic function info for selected binary.
| REfr <fn_addr> <new_name> # Rename function with given function id to given name.
| REfs <function_name> <min_confidence>=95 # RevEng.AI ANN functions similarity search.
| REart                   # Show RevEng.AI ASCII art.
```

### `REh` : Health Check

Can be used to check connection status with RevEng.AI servers. It is not required to be executed
before using the plugin. This comand does not require a binary opened before it's execution as well.

### `REm` : Get Available AI Models

Creating new analysis requires AI models. Currently available AI models are loaded at the start of the
plugin so an internet connection is required, otherwise a plugin restart is necessary for this command to work.

```
[0x00000000]> REm
binnet-0.3-x86-windows
binnet-0.3-x86-linux
binnet-0.3-x86-macos
binnet-0.3-x86-android
binnet-0.4-x86-windows
binnet-0.4-x86-linux
binnet-0.4-x86-macos
binnet-0.4-x86-android
```

### `REa` : Create Analysis

This command requires an open binary. This will upload a binary to RevEng.AI servers and then
create an analysis for the uploaded binary file. Wait for analysis operation to complete before
using using any related API.

Analysis progress can be tracked in detail on RevEngAI's dashboard. Any command that requires
a binary id will automatically fail and display an analysis status if available.

If you save a radare project after creating a new analysis, the analysis ID automatically gets
stored in the radare project and is automatically loaded when you open the project.

### `REau` : Auto Analysis

After analysis is complete, the command will get function matches for all functions in a binary,
that have a confidence greater than that provide as command argument and rename the current names
with best match.

Save your radare project after performing an auto-analysis. Or when you re-open the binary, apply
the existing analysis using the command below.

### `REap` : Apply Existing Analysis

Anyone with access to an existing analysis can apply the analysis to a binary in the plugin.
This will automatically perfrom function renames for all existing functions in order to
sync names between RevEngAI server and radare.

If you save a radare project after creating a new analysis, the analysis ID automatically gets
stored in the radare project and is automatically loaded when you open the project.

### `REfl` : Function List

To print the names and boundaries of current functions in the binary in radare, you do `afl`.
This command is similar to `afl`, but it fetches the names from RevEng.AI servers instead of
radare project.

### `REfr` : Function Rename

Rename a function in RevEng.AI analysis. Renames function in both radare and RevEngAI.

### `REfs` : Function Search

Searches for functions similar to provided function and have a confidence greater than
the provided `min_confidence`.

### `REart`

This is the most awesome command. Tag us on twitter with a screenshot of the output of this command :-)
if you like what we're doing here :-)

---
