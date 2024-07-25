#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
from pwn import *
import time
import serial
from Crypto.Hash import HMAC, SHA256
from shutil import get_terminal_size

from util import *

RESP_OK = b"\x00"
FRAME_SIZE = 84

key = 'hmac'

def send_metadata(ser: serial.Serial, metadata, debug=False):
    id = 0b00

    # this reads important metadata FROM THE PROTECTED FIRMWARE to be written on flash and recorded. IT IS NOT THE BINARY
    version = u16(metadata[:2], endian='little')
    bytesize = u16(metadata[2:], endian='little')
    num_packets = len(range(0, len(size), FRAME_SIZE))

    print(f"Sending begin frame ({id})\n\tVersion: {version}\n\tFirmware Size: {bytesize} bytes\n")

    begin = bytearray(84)

    # Populate with metadata
    begin[0] = id # id
    begin[1] = p8(version, endian='little') # version
    begin[2:4] = p16(num_packets, endian='little') # num_packets
    begin[4:6] = p16(bytesize, endian='little') # bytesize

    # sign using metadata slice
    h = HMAC.new(key, digestmod=SHA256)
    h.update(begin[0:4])
    print(f"Signed BEGIN with signature of size {h.digest_size}")
    begin[6:38] = h.digest()

    begin[38:] = b'x\00' * (84-38)

    # send the properly constructed BEGIN frame
    ser.write(begin)

    resp = ser.read(1)
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser: serial.Serial, frame: bytearray, debug=False):
    assert(len(frame) == 84)
    # first_byte = u8(frame[0], endian='little')

    # length = first_byte & 0x3f
    # id = (first_byte >> 6)
    # assert(id == 2)


    # print(f"Id: {id}\nLength: {length}\n")

    ser.write(frame)

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def send_release_message(ser: serial.Serial, frame: bytearray, debug=False):
    assert(len(frame) == 84)

    first_byte = u8(frame[0], endian='little')
    id = (first_byte >> 6)

    assert(id == 0b01)

    message = unpack(frame[1:83], 82, endian='little')

    print(f"Message: {message}\n")

    ser.write(frame)

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def update(ser: serial.Serial, infile, debug):
    """

    
    NEVER WROTE THE MESSAGE. BIG ERROR!!!


    """
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    if ser.read(1).decode() != "U":
        return

    print("Updating. Woohoo!!")

    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:4]
    firmware = firmware_blob[4:]

    send_metadata(ser, metadata, debug=debug)
    send_release_message(ser, )

    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        frame = firmware[frame_start : frame_start + FRAME_SIZE]

        send_frame(ser, frame, debug=debug)

        print(f"Writing frame {idx} of ({len(frame)} bytes)" + "[{:{}}]\r".format('▒'*int(idx), len(firmware) // FRAME_SIZE), end='')

    print("Done writing firmware.")
    # No need for final ok sending becasue we assume server already can tell from end frame

    resp = ser.read(1)  # Wait for an OK from the bootloader
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
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
        print("Loaded serial connection: {ser}")
    else:
        ser = serial.Serial("/dev/ttyACM0", 115200)

    update(ser=ser, infile=args.firmware, debug=args.debug)
    our_beloved()
    ser.close()
