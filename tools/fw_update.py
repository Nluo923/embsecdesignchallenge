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

from util import *

ser = serial.Serial("/dev/ttyACM0", 115200)

RESP_OK = b"\x01"
FRAME_SIZE = 84

def send_metadata(ser, metadata, debug=False):
    assert(len(metadata) == 84)
    # first_byte = u8(metadata[0], endian='little')
    # id = (first_byte >> 6)
    # assert(id == 0)

    # version = u8(metadata[1], endian='little')

    # num_packets = u16(metadata[2:4], endian='little')

    # signature = unpack(metadata[4:36], 32, endian='little')

    # print(f"Id: {id}\nVersion: {version}\nSize: {num_packets} packets\n")

    if debug:
        print(metadata)

    ser.write(metadata)

    resp = ser.read(1)
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
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

def send_release_message(ser, frame, debug=False):
    assert(len(frame) == 84)

    first_byte = u8(frame[0], endian='little')
    id = (first_byte >> 6)

    assert(id == 2)

    message = unpack(frame[1:83], 82, endian='little')

    print(f"Id: {id}\nMessage: {message}\n")

    ser.write(frame)

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def update(ser, infile, debug):
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

    metadata = firmware_blob[:FRAME_SIZE]
    firmware = firmware_blob[FRAME_SIZE:]

    send_metadata(ser, metadata, debug=debug)

    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        frame = firmware[frame_start : frame_start + FRAME_SIZE]

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx}")

    print("Done writing firmware.")
    # No need for final ok sending becasue we assume server already can tell from end frame

    resp = ser.read(1)  # Wait for an OK from the bootloader
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    update(ser=ser, infile=args.firmware, debug=args.debug)
    ser.close()
