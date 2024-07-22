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

FILE_DIR = pathlib.Path(__file__).parent.absolute()


def copy_initial_firmware(binary_path):
    """
    Copy the initial firmware binary to the bootloader build directory
    Return:
        None
    """
    # Change into directory containing tools
    os.chdir(FILE_DIR)
    bootloader = FILE_DIR / '..' / 'bootloader'
    shutil.copy(binary_path, bootloader / 'src' / 'firmware.bin')

def arrayize(binstr):
    values = "{" + ','.join([hex(char) for char in binstr]) + "}"
    return values
    
def make_bootloader():
    """
    Build the bootloader from source.

    Return:
        True if successful, False otherwise.
    """
    # Change into directory containing bootloader.
    bootloader = FILE_DIR / '..' / 'bootloader'
    os.chdir(bootloader)
    
    # Generates hmac_key, aes_key, and iv
    # Crypto.Random.get_random_bytes is cryptographically strong
    hmac_key = Crypto.Random.get_random_bytes(48)
    aes_key = Crypto.Random.get_random_bytes(16)
    iv = Crypto.Random.get_random_bytes(16)
    aad = Crypto.Random.get_random_bytes(16)
    
    # Writing the keys and iv to secret_build_output
    with open("secret_build_output.txt", "wb") as f:
        f.write(hmac_key + aes_key + iv + aad)
    
    
    subprocess.call('make clean', shell=True)
    # Enables the iv and keys to be passed into the bootloader.c file
    status = subprocess.call(f'make HMAC={arrayize(hmac_key)} KEY={arrayize(aes_key)} INIT_IV={arrayize(iv)} AAD={arrayize(aad)}', shell=True)
    # status = subprocess.call('make')
    
    # Return True if make returned 0, otherwise return False.
    return (status == 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootloader Build Tool')
    parser.add_argument("--initial-firmware", help="Path to the the firmware binary.", default=None)
    args = parser.parse_args()
    if args.initial_firmware is None:
        binary_path = FILE_DIR / '..' / 'firmware' / 'firmware' / 'gcc' / 'main.bin'
    else:
        binary_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(binary_path):
        raise FileNotFoundError(
            "ERROR: {} does not exist or is not a file. You may have to call \"make\" in the firmware directory.".format(
                binary_path))

    copy_initial_firmware(binary_path)
    make_bootloader()