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

secrets = open("../bootloader/secret_build_output.txt", 'rb').read()
hmac_key = secrets[0:48]
aes_key = secrets[49:65]
initial_iv = secrets[66:]

def send_metadata(ser: serial.Serial, metadata: bytes, debug=False):
    print("BEGIN")
    assert(len(metadata) == 4)

    id = 0b00000000

    # this reads important metadata FROM THE PROTECTED FIRMWARE to be written on flash and recorded. IT IS NOT THE BINARY
    version = u8(metadata[0:1], endian='little')
    bytesize = u16(metadata[2:], endian='little')
    num_packets = len(range(0, bytesize, DATA_SIZE))

    print(f"Sending begin frame ({id})\n\tVersion: {version}\n\tFirmware Size: {bytesize} bytes\n")

    begin = b""
    # Populate with metadata
    begin += p8(id) # id
    begin += p8(version) # version
    begin += p16(num_packets, endian='little') # num_packets
    begin += p16(bytesize, endian='little') # bytesize

    # sign using version + num_packets + bytesize
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(begin[1:6])
    print(f"\tSigned BEGIN with signature of size {h.digest_size}\n\t{h.hexdigest()}")
    begin += h.digest()

    begin += b'\0' * (84-38)

    # send the properly constructed BEGIN frame
    assert(len(begin) == 84)
    enc = AES.new(aes_key, AES.MODE_CBC, iv=initial_iv)
    encrypted_begin = enc.encrypt(pad(begin, AES.block_size)) # pad to 96 bytes
    ser.write(encrypted_begin)
    print("\tWrote BEGIN frame")

    resp = ser.read(1)
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("\tERROR: Bootloader responded with {}".format(repr(resp)))
    else:
        print(f"\tBEGIN OK")


def send_frame(ser: serial.Serial, data: bytes, nonce: int, debug=False):
    id = len(data)

    if len(data) == DATA_SIZE:
        id |= 0b10000000
    else:
        id |= 0b11000000

    nonce = p16(nonce, endian='little')
    
    data_frame = b''
    data_frame += p8(id)
    data_frame += nonce
    data_frame += data.ljust(DATA_SIZE, b'\0')
    data_frame += b'\0' # padding

    # sign with nonce + data, containing its padding too. i.e. fixed size inputs.
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(data_frame[1 : 3 + DATA_SIZE])
    data_frame += h.digest()
    print(f"\tSigned frame {nonce} with signature of size {h.digest_size}\n\t{h.hexdigest()}")

    assert(len(data_frame) == 84)
    enc = AES.new(aes_key, AES.MODE_CBC, iv=initial_iv)
    encrypted_data_frame = enc.encrypt(pad(data_frame, AES.block_size)) # pad to 96 bytes
    ser.write(encrypted_data_frame)

    if debug:
        print_hex(data_frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def send_release_message(ser: serial.Serial, message: bytes, debug=False):
    id = 0b01000000

    frame = bytearray(84)
    frame[0] = id
    for i in range(1, min(len(message), 84)):
        frame[i] = message[i-1]
    frame[-1] = 0x00
    print(f"Message (len {len(message)}): {message}\n")

    ser.write(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def update(ser: serial.Serial, infile, debug):
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")

    inc = ser.read(1).decode()
    while inc != "U":
        print(f"\tGot a byte {inc}")
        inc = ser.read(1).decode()

    print("Updating. Woohoo!!")

    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:4]

    send_metadata(ser, metadata, debug=debug)

    null_term = 4
    while firmware_blob[null_term] != 0: # couldn't tell you why this works despite writing being the opposite
        null_term += 1

    print(f"Firmware Message: {firmware_blob[4:null_term+1]}")

    send_release_message(ser, firmware_blob[4:null_term+1]);

    firmware = firmware_blob[null_term+1:]
    for idx, frame_start in enumerate(range(0, len(firmware), DATA_SIZE)):
        frame = firmware[frame_start : frame_start + DATA_SIZE]

        print(f"Writing frame {idx} ({len(frame)} bytes)" + "[{:{}}]".format('▒'*int(idx), len(firmware) // DATA_SIZE))
        send_frame(ser, frame, idx, debug=debug)

    print("Done writing firmware.")

    resp = ser.read(1)  # Wait for an OK from the bootloader
    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to end frame with {}".format(repr(resp)))
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
