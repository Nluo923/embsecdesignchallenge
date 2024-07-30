# Current Encryption Format

**J**oint
**A**lgorithm
**Y**ielding
**D**ata
**E**ncryption
**N**etwork

Encryption

-   [x] Many Flags
-   [x] Caesar
-   [x] Railfence
-   [x] Alphabet modulus
-   [x] Enigma
-   [x] AES-128
-   [x] Morse
-   [x] Numbers

Decryption

-   [ ] Many Flags
-   [ ] Caesar
-   [ ] Railfence
-   [ ] Alphabet modulus
-   [ ] Enigma
-   [ ] AES-128
-   [ ] Morse
-   [ ] Numbers

---

# Frame Format

All frames are signed to ensure that they are indeed the correct data that was encrypted with the secrets provided at build time.

Each frame has one byte allocated to store the individual frame's metadata.

The first few bits determine how the frame should be interpreted by the bootloader.
For the data frames, length is provided in the remaining bits.

<blockquote>

**Begin**

The BEGIN frame stores metadata used to verify all of the incoming data frames.

```
<84 bytes>

ID,UNK      :: 1 byte         Composed of first 2 bits ID, other 6 bits useless
VER         :: 2 bytes        Version which shall be used to preserve its invariance
NUM_PACKETS :: 2 bytes        Number of incoming data packets, this includes the ending frame.
BYTESIZE    :: 2 bytes        Bytesize of firmware.
SIG         :: 32 bytes       Sign the metadata, because we are cool like that.
PAD         :: 45 bytes       For comfort

  0x00      0x01      0x03              0x05      0x07   0x27      0x54
   ^         ^         ^                 ^         ^      ^         ^
   | ID      | VER     | NUM_PACKETS     |BYTESIZE | SIG  |  PAD    |
   [--------][--------][----------------][--------][~~~~~][========]|
       |
       |
  [ 00 ...... ]
bits: ID(2)  UNK(6)
```

</blockquote>

---

<blockquote>

**Message**

```
<84 bytes>

ID,UNK      :: 1 byte
MESSAGE     :: 82 byte
TERM        :: 1 byte          Null terminator to prevent Shenanigans

Don't care about no encryption

  0x00      0x01               0x53      0x54
   ^         ^                  ^         ^
   | ID,UNK  |     MESSAGE      |  TERM   |
   [--------][.................][00000000]|
       |
       |
  [ 01 ...... ]
bits: ID(2)

```

</blockquote>

---

<blockquote>

**Data**

```
<84 bytes>

ID,LEN      :: 1 byte         Composed of first 2 bits ID and 6 bit LEN
NONCE       :: 2 bytes
DATA        :: 48 bytes       For ID=01, will be 48 bytes. For ID=11, will be 0-48.
                              Indicates length of meaningful data bytes to read from
PAD         :: 1 byte
SIG         :: 32 bytes       Signature of entire frame which will be used to ensure the following:
                                - This frame was encrypted with the correct secret
                                - This frame is not forged


  0x00      0x01      0x03               0x33      0x34  0x54
   ^         ^         ^                  ^         ^     ^
   | ID,LEN  | NONCE   |      DATA        |   pad   | SIG |
   [--------][--------][.................][========][~~~~~]
       |
       |
  [ 10 ...... ]
bits: ID(2)  LEN(6) :: 48
```

Each DATA frame stores a nonce, which verifies its order and unique identity. The _ith_ frame has a nonce _i_.

---

**End**

```
<84 bytes>

  0x00      0x01
   ^         ^
   | ID,LEN  |    ...  same
   [--------]|
       |
       |
  [ 11 ...... ]
bits: ID(2)  LEN(6) :: 0-48
```

</blockquote>

This is essentially another dataframe with the leftover data. It will be interpreted as such, except the ID is marked to indicate that this is the case. The bootloader must account for any padding in the data segment. It can also be the case that LEN = 0, and in this case no data shall be written.

---

# Binary Format

This describes the firmware_protected.bin file produced by [fw_protect.py](tools/fw_protect.py) and interpreted by [fw_update.py](tools/fw_update.py) to be sent as packets.

```

- 2 byte LE                              version
- 2 byte LE                              firmware bytesize
- Variable length, null-terminated       message
- Firmware

```

---

# Signing

Packets, if necessary, are signed with HMAC-SHA256, outputting a 32-byte signature.

> **BEGIN FRAME**
>
> Input to HMAC is [version, num_packets, and bytesize] concatenated. 6 bytes

> **DATA FRAME**
>
> Input to HMAC is [nonce, data] concatenated. 50 bytes

---

# Exchange

The exchange goes as follows

```
Python                                Bootloader
> U
                                    U          <
                                    Begin update
> BEGIN FRAME
                                    Verify
                                    OK         <
> MESSAGE FRAME
                                    Verify
                                    OK         <
> DATA FRAME
                                    Verify
                                    OK         <
                                 if END    break
                               Verify framecount
                                    OK         <
                           write to flash memory

```
