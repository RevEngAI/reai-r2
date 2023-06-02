#!/usr/bin/python3
from __future__ import print_function
import r2lang
import r2pipe
from tempfile import NamedTemporaryFile
from string import ascii_uppercase
from json import dumps
from sys import argv
from os import system
import traceback
import requests
import json
from reait import api

__author__ = "James Patrick-Evans"
__version__ = 0.01

r2 = r2pipe.open()


def r2_binary():
    """
    Return path to opened binary file
    """
    opened_file = list(filter(lambda x: x['fd'] == 3, r2.cmdj('oj')))
    if len(opened_file) == 0:
        raise RuntimeError("Cannot determine file path of binary to analyse")

    fpath = opened_file['uri']
    return fpath

def analyse(command):
    """
        Analyze currently open binary
        e.g. aR
    """
    fpath = r2_binary()
    return api.RE_analyse(fpath)

def delete(command):
    fpath = r2_binary()
    return api.RE_delete(fpath)

def nearest_symbols(command):
    """
        Get function name suggestions for each function
    """
    f_suggestions = api.RE_nearest_symbols(embedding, 5, collections)
    # apply names using comments

    # add all name suggestions with probabilities as comments
    for vaddr, suggestion in f_suggestions.items():
        name, prob = suggestion
        r2.cmd(f"CC '{name} - {prob}' @{vaddr}")

    # rename function most confident name
    #r2.cmd(f"afn best_name @fnc.func0000000")


def r2reait(_):
    """Build the plugin"""

    def process(command):
        print(f"reait: received command {command}")
        try:
            if not command[:2] == "aR":
                return 0

            sub_cmd = command[2:]

            # Parse arguments
            if sub_cmd[0] == "?":
                print("""
                      Usage aR [RmcnnuSsbom] [...]
                      | aR                        - Analyze executable with RevEng.AI
                      | aRm binnet-crypto         - Set RevEng.AI model to use for analysis e.g. binnet-crypto
                      | aRc ^libcrypto(.*)        - Set RevEng.AI collections regex
                      | aRnn                      - Search for the closest function matches to the current function
                      | aRnn @ *0x002ae           - Find the top 5 closest matches for function at address
                      | aRnn 3 @ sym.func_0x02ae  - Find the 3 closest functions for symbol
                      | aRu h/m/l/0.8             - Unstrip binary with high/medium/low/float confidence
                      | aRS                       - Generate a RevEng.AI binary signature
                      | aRSnn                     - Find closest binary files to executable
                      | aRsbom                    - Generate SBOM of embedded third party libraries
                      | aRd                       - Delete binary from RevEng.AI account
                      """)
            if sub_cmd == "" or sub_cmd[0] == " ":
                analyse(sub_cmd[1:])
            elif command.startswith("aRann"):
                #RE_nearest_symbols(command)
                pass
            elif command.startswith("aRej"):
                #RE_get_embeddings(command)
                pass
            elif command.startswith("aRc"):
                #RE_get_software_components(command)
                pass
            elif command.startswith("aRd"):
                delete(command)
        except Exception as e:
            print(traceback.format_exc())

        return 1

    return {"name": "r2reait",
            "author": __author__,
            "version": __version__,
            "licence": "GPLv3",
            "desc": "RevEng.AI Radare2 plugin",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2reait):
    print("An error occurred while registering r2reait plugin!")
else:
    print("Registering reait plugin!")
