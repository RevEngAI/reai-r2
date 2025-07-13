#!/usr/bin/env python3
import r2pipe
import sys
import os
import argparse

import re

def test_cmd_exists(r2, rcmds):
    failed = 0

    for cmd  in rcmds:
        oj = r2.cmd2(f'{cmd}?')
        if oj.error:       
            failed += 1
            print(f"[ERROR] NOT FOUND '{cmd}' or ERRORED OUT")
        else:
            print(f"[SUCCESS] FOUND '{cmd}'")

    if failed:
        print(f"[FAIL] {failed} out of {len(required_cmds)} required commands not found!")
        return False
    else:
        print("[PASS] All required commands found")
        return True

def test_plugin_init_cmd(r2):
    """
    Test REi command

    Requires:
        - `E2E_API_KEY` environment variable set
        - `E2E_API_URL` environment variable set
    """

    # get API key from 
    if 'E2E_API_KEY' in os.environ.keys():
        api_key = os.environ['E2E_API_KEY']
    else:
        print('[ERROR] RevEngAI API key not provided in environment. "E2E_API_KEY" is required in environment.')
        return False

    if 'E2E_API_URL' in os.environ.keys():
        api_url = os.environ['E2E_API_URL']
    else:
        print('[ERROR] RevEngAI API url not provided in environment. "E2E_API_URL" is required in environment.')
        return False

    res = True
    res &= r2.cmd('REi') is not None          # Will fail and print log messages

    out = r2.cmd(f'REi {api_key}').strip()
    
    if 'ERROR:' in out:
        print("[ERROR] REi <key> returned unexpected output")
        res = False
    else:
        print("[SUCCESS] REi <key> executed as expected")
    
    try:
        with open(os.path.expanduser('~/.creait'), 'r') as config:
            content = config.read()
            if api_key not in content:
                print('[ERROR] API key not found in config file. Plugin not initialized correctly.')
                res = False
            else:
                print('[SUCCESS] API key found in config file.')
                with open(os.path.expanduser('~/.creait'), 'w') as f:
                    f.write(f'api_key={api_key}\nhost={api_url}\n') 
                res &= True
    except FileNotFoundError:
        print('[ERROR] Creait config file not found!')

    return res


# Basic argument parser
parser = argparse.ArgumentParser("radare2_test.py")
parser.add_argument("bin", help="Binary to open R2Pipe over", type=str)
args = parser.parse_args()

failed = 0

# Run all tests
r2 = r2pipe.open(args.bin)
print(f"Using binary '{args.bin}'")

if not test_cmd_exists(r2, ['REf', 'REa', 'REc', 'REcs', 'REca', 'REcd', 'RE', 'REb']):
    failed += 1

if not test_cmd_exists(r2, ['REa', 'REf', 'REb', 'REc', 'REd', 'REh', 'REi', 'REm', 'REu']):
    failed += 1

if not test_plugin_init_cmd(r2):
    failed += 1
    
r2.quit()

if failed:
    sys.exit(1)    
else:
    sys.exit(0)
