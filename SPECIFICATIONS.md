# Frame Format

All frames are signed to ensure that they are indeed the correct data that was encrypted with the secrets provided at build time.

Each frame has one byte allocated to store the individual frame's metadata.

The first few bits determine how the frame should be interpreted by the bootloader.
For the data frames, length is provided in the remaining bits.

<blockquote>

**Begin**

```
<36 bytes>

ID,UNK      :: 1 byte         Composed of first 2 bits ID, other 6 bits useless
VER         :: 1 bytes        Version which shall be used to preserve its invariance
NUM_PACKETS :: 2 bytes        Number of incoming data packets, this includes the ending frame.
SIG         :: 32 bytes       Sign the metadata, because we are cool like that.

  0x00      0x01      0x02              0x04  0x24
   ^         ^         ^                 ^     ^
   | ID      | VER     | NUM_PACKETS     | SIG |
   [--------][--------][----------------][~~~~~]
       |
       |
  [ 00 ...... ]
bits: ID(2)  UNK(6)
```

</blockquote>

The BEGIN frame stores metadata used to verify all of the incoming data frames.

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
  [ 01 ...... ]
bits: ID(2)  LEN(6) :: 48
```

Each DATA frame stores a nonce, and while Reading west would verify that the nonce is both sequentially valid such that if any char lies in some sentence, it would not be able to be duplicated or moved around. In this manner, the data is convicted to be authentic despite being signed per individual frame, and any offenders would be identified for the lifetime of the program and rejected at the end.

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
