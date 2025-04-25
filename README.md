# RevEng.AI Radare Plugin

RevEng.AI plugin for Radare.

## Installation

### R2PM

The easiest and prefered way to install plugins in [radare2](https://github.com/radareorg/radare2) is via r2pm:

```
r2pm -Uci reai-r2
```

Alternatively you can also try with docker or the manual steps

### Docker

Don't want to go through all the manual hassle? We have a dockerfile as well.
Just do :

```bash
git clone --recurse-submodules https://github.com/revengai/reai-r2 &&
cd reai-r2 && docker build --build-arg REVENG_APIKEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -t reai-r2 . &&
docker run -v /tmp/userdata:/home/revengai/userdata -it reai-r2
```

Any subsequent runs will automatically enter into Radare2 shell with the following command :

```bash
docker run -v /tmp/userdata:/home/revengai/userdata -it reai-r2
```

Users can open binaries into radare2 using the `o` command group.

This will get you a working installation of the radare plugin in a single command!

- Store the files you want to access into `/tmp/userdata` directory of host,
  and access these files through `~/userdata` inside the docker container.

- Make sure to put correct value for `apikey` build arg. You can also change it after installing
  though, through directly editing config file, or using the `REi` command inside the plugin.

### Manual

The build scripts assume default settings that'll work for most users. For advanced users,
who wish to change the intallation process, they may fetch the script and make modifications
and then perform the installation.

```bash
# On Linux/MacOSX
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-r2/refs/heads/master/Scripts/Build.sh | bash

# On Windows
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr - UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-r2/refs/heads/master/Scripts/Build.ps1')
```

### Dependencies

Before running any of the above commands, you must install cmake, make, ninja, meson, gcc/g++, pkg-config, libcurl (development package), and [radare](https://github.com/radareorg/radare2).

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
