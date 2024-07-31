#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwn import *
import sys
import os.path
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

secrets = open("../bootloader/secret_build_output.txt", 'rb').read()
hmac_key = secrets[0:48]
aes_key = secrets[49:65]
initial_iv = secrets[66:]

FRAME_SIZE = 84
DATA_SIZE = 48

frames = b""

def begin_frame(version, bytesize):
    id = 0b00000000
    num_packets = len(range(0, bytesize, DATA_SIZE))
    print(f"BEGIN frame ({id})\n\tVersion: {version}\n\tFirmware Size: {bytesize} bytes\n\tPackets: {num_packets}\n")

    frame = b""
    # Populate with metadata
    frame += p8(id) # id
    frame += p16(version, endian='little') # version
    frame += p16(num_packets, endian='little') # num_packets
    frame += p16(bytesize, endian='little') # bytesize

    # sign using version + num_packets + bytesize
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(frame[1:7])
    print(f"\tSigned BEGIN with signature of size {h.digest_size}\n\t{h.hexdigest()}")
    frame += h.digest()

    frame += b'\0' * (84-39)

    assert(len(frame) == 84)
    enc = AES.new(aes_key, AES.MODE_CBC, iv=initial_iv)
    encrypted_frame = enc.encrypt(pad(frame, AES.block_size)) # pad to 96 bytes
    global frames
    frames += encrypted_frame
    print("\tWrote BEGIN frame")

def message_frame(message: bytes):
    id = 0b01000000

    frame = b""
    frame += p8(id)
    frame += message[:83]
    frame += b'\x00' * (83 - len(message))
    assert(len(frame) == 84)
    print(f"Message (len {len(message)}): {message}\n")

    global frames
    frames += frame

def data_frame(data: bytes, nonce: int):
    assert(len(data) <= DATA_SIZE)
    print(f"Writing frame {nonce} ({len(data)} bytes) {'▒'*int(nonce)}")

    id = len(data)

    if len(data) == DATA_SIZE:
        id |= 0b10000000
    else:
        id |= 0b11000000

    print("{:b}".format(id))
    
    nonce = p16(nonce, endian='little')

    frame = b''
    frame += p8(id)
    frame += nonce
    frame += data.ljust(DATA_SIZE, b'\x00')
    frame += b'\x00' # padding

    # sign with nonce + data, containing its padding too. i.e. fixed size inputs.
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(frame[1 : 3 + DATA_SIZE])
    frame += h.digest()

    print(f"\tSigned with signature of size {h.digest_size}\n\t{h.hexdigest()}")
    assert(len(frame) == 84)

    enc = AES.new(aes_key, AES.MODE_CBC, iv=initial_iv)
    encrypted_frame = enc.encrypt(pad(frame, AES.block_size)) # pad to 96 bytes
    global frames
    frames += encrypted_frame

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    firmware = open(infile, 'rb').read()

    begin_frame(version, len(firmware))
    message_frame(message.encode()[:83])
    for idx, frame_start in enumerate(range(0, len(firmware), DATA_SIZE)):
        data = firmware[frame_start : frame_start + DATA_SIZE]
        data_frame(data, idx)

    # Write firmware blob to outfile
    with open(outfile, "wb+") as outfile:
        outfile.write(frames)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True, type=int)
    parser.add_argument("--message", help="Release message for this firmware (Max 82 chars).", required=True)
    args = parser.parse_args()

    if os.path.isfile(args.infile) is None:
        print(f"{args.infile} doesn't exist")
        sys.exit(-1)
    
    if os.path.isfile(args.outfile) is None:
        print(f"{args.outfile} doesn't exist")
        sys.exit(-1)

    if args.version < 0 or args.version > 2**16 - 1:
        print(f"Invalid version")
        sys.exit(-1)

    if len(args.message) > 82:
        print("The message, it's too long...", file=sys.stderr)
        sys.exit(-1)

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
