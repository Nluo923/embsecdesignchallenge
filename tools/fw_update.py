# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

import argparse
from pwn import *
import time
import serial
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from shutil import get_terminal_size

from util import *

RESP_OK = b"\x00"
FRAME_SIZE = 84
DATA_SIZE = 48
ENCRYPTED_FRAME_SIZE = 96

def send_metadata(ser: serial.Serial, encrypted_begin: bytes, debug=False):
    assert(len(encrypted_begin) == ENCRYPTED_FRAME_SIZE)
    print("BEGIN")

    ser.write(encrypted_begin)
    print(f"\t{encrypted_begin}")
    print("\tWrote BEGIN frame")

    resp = ser.read(1)
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("\tERROR: Bootloader responded with {}".format(repr(resp)))
    else:
        print(f"\tBEGIN OK")

def send_frame(ser: serial.Serial, encrypted_data: bytes):
    assert(len(encrypted_data) == ENCRYPTED_FRAME_SIZE)

    ser.write(encrypted_data)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    if resp != RESP_OK:
        raise RuntimeError("\tERROR: Bootloader responded with {}".format(repr(resp)))

def send_release_message(ser: serial.Serial, message: bytes, debug=False):
    assert(len(message) == FRAME_SIZE)
    print(f"MESSAGE: {message.decode(encoding="utf-8")}\n")

    ser.write(message)

    resp = ser.read(1)  # Wait for an OK from the bootloader
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("\tERROR: Bootloader responded with {}".format(repr(resp)))
    else:
        print(f"\tMESSAGE OK")

def update(ser: serial.Serial, infile, debug):
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")

    inc = ser.read(1).decode()
    while inc != "U":
        print(f"\tGot a byte {inc}")
        inc = ser.read(1).decode()

    print("Updating")

    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    send_metadata(ser, firmware_blob[ : ENCRYPTED_FRAME_SIZE], debug=debug)
    send_release_message(ser, firmware_blob[ENCRYPTED_FRAME_SIZE : ENCRYPTED_FRAME_SIZE + FRAME_SIZE]);

    encrypted_firmware = firmware_blob[ENCRYPTED_FRAME_SIZE + FRAME_SIZE : ]
    for idx, frame_start in enumerate(range(0, len(encrypted_firmware), ENCRYPTED_FRAME_SIZE)):
        encrypted_frame = encrypted_firmware[frame_start : frame_start + ENCRYPTED_FRAME_SIZE]

        print(f"\rWriting frame {idx}" + " [{:{}}]".format('▒'*(idx+1), len(encrypted_firmware) // ENCRYPTED_FRAME_SIZE), end='')
        send_frame(ser, encrypted_frame)

    print("\nDone writing firmware.")

    resp = ser.read(1)  # Wait for an OK from the bootloader
    time.sleep(0.1)

    print(resp + ser.read_all())

    # if resp != RESP_OK:
        # raise RuntimeError("\tERROR: Bootloader responded with {}".format(repr(resp)))
    return ser

def our_beloved():
    width = get_terminal_size()[0]
    jydn = open("../media/beloved.txt", "r").read().splitlines()
    jydn[4] += "      our beloved"
    jydn = [l[:width] if len(l) > width else l for l in jydn]

    sys.stdout.write("\n".join(jydn))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    parser.add_argument("--devname", help="wtf is an ACM", required=False)
    args = parser.parse_args()

    if args.devname is not None:
        ser = serial.Serial(f"/dev/{args.devname}", 115200)
        print(f"Loaded serial connection: {ser.port}")
    else:
        ser = serial.Serial("/dev/ttyACM0", 115200)

    update(ser=ser, infile=args.firmware, debug=args.debug)
    # our_beloved()
    ser.close()
