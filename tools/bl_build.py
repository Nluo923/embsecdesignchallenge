#!/usr/bin/env python
"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import Crypto.Random

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

def arrayize(binstr):
    values = "{" + ','.join([hex(char) for char in binstr]) + "}"
    return values
    
def make_bootloader():
    # Change into directory containing bootloader.
    os.chdir(BOOTLOADER_DIR)
    
    hmac_key = Crypto.Random.get_random_bytes(48)
    aes_key = Crypto.Random.get_random_bytes(16)
    iv = Crypto.Random.get_random_bytes(16)
    
    # Writing the keys and iv to secret_build_output
    with open("secret_build_output.txt", "wb") as f:
        f.write(hmac_key + b"\n" + aes_key + b"\n" + iv)
    
    # Writing the keys and iv to header file
    with open("inc/keys.h", "wb") as f:
        to_write = f"""#ifndef SECRETS_H
#define SECRETS_H
const uint8_t HMAC_KEY[{len(hmac_key)}] = {arrayize(hmac_key)};
const uint8_t AES_KEY[{len(aes_key)}] = {arrayize(aes_key)};
const uint8_t INITIAL_IV[{len(iv)}] = {arrayize(iv)};
#endif
"""
        f.write(bytes(to_write, encoding='UTF-8'))
    
    subprocess.call('make clean', shell=True)
    status = subprocess.call('make')
    os.chdir(os.path.join(BOOTLOADER_DIR, 'inc'))
    os.remove('keys.h')
    
    return (status == 0)


if __name__ == '__main__':
    make_bootloader()