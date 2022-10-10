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

__author__ = "James Patrick-Evans"
__version__ = 0.01

r2 = r2pipe.open()

RE_h = {
    'binary' : None,    # current binary hash
    'apikey' : 'libr3'  # users api key
}

def reveng_req(r: requests.request, end_point: str, data=None, ex_headers: dict = None):
    global RE_h
    url = f"https://api.reveng.ai/{end_point}"
    headers = { "Authorization": f"Bearer {RE_h['apikey']}" }
    if ex_headers:
        headers.update(ex_headers)
    resp = r(url, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()

def binary_id():
    """Get the SHA256 hash of the current binary"""
    return r2.cmdj('itj')['sha256']

def RE_delete(command):
    """
        Delete analysis results for Binary ID in command
        Binary ID defaults to current binary
        e.g. aRd 1f0ee425614e009ca48cd81d0ca332fe5e9816628c93c46a0e90c8dcf65ead42
    """
    binary_id = binary_id()
    args = command.split(' ')[1:]
    if len(args) >= 1:
        binary_id = args[0]

    return reveng_req(requests.delete, f"/{binary_id}")

def RE_analyse(command):
    """
        Analyze currently open binary
        e.g. aR
    """
    opened_file = list(filter(lambda x: x['fd'] == 3, r2.cmdj('oj')))
    if len(opened_file) == 0:
        raise RuntimeError("Cannot determine file path of binary to analyse")
    fpath = opened_file['uri']
    return reveng_req(requests.post, f"/analyse", data=open(fpath, 'rb').read(), ex_headers={"ContentType": "application/binary"})

def RE_nearest_symbols(command):
    """
        Get function name suggestions for each function
    """
    f_suggestions = reveng_req(requests.get, f"/ann/{binary_id()}")
    # apply names using comments

    # add all name suggestions with probabilities as comments
    for vaddr, suggestion in f_suggestions.items():
        name, prob = suggestion
        r2.cmd(f"CC '{name} - {prob}' @{vaddr}")

    # rename function most confident name
    #r2.cmd(f"afn best_name @fnc.func0000000")


def r2revengai(_):
    """Build the plugin"""

    def process(command):
        try:
            if not command in ("aR", #analyse binary
                    "aRann",    # get nearest neighbors, add closest symbols for each symbol
                    "aRej",     # get embeddings as json
                    "aRc",      # get software components
                    "aRd"       # securely delete binary and analysis results aRd {hash}
                    ):
                return 0

            # Parse arguments
            if command == "aR":
                RE_analyse()
            elif command.startswith("aRann"):
                RE_nearest_symbols(command)
            elif command.startswith("aRej"):
                RE_get_embeddings(command)
            elif command.startswith("aRc"):
                RE_get_software_components(command)
            elif command.startswith("aRd"):
                RE_delete(command)
        except Exception as e:
            print(traceback.format_exc())

        return 1

    return {"name": "r2revengai",
            "author": "James Patrick-Evans",
            "version": 0.10,
            "licence": "GPLv3",
            "desc": "radare2 RevEng.AI plugin",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2revengai):
    print("An error occurred while registering r2reveng.ai plugin !")
