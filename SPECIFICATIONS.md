# Frame Format

All frames are signed to ensure that they are indeed the correct data that was encrypted with the secrets provided at build time.

Each frame has one byte allocated to store the individual frame's metadata.

The first few bits determine how the frame should be interpreted by the bootloader.
For the data frames, length is provided in the remaining bits.

<blockquote>

**Begin**

```
<36 bytes>

  0x00      0x01      0x03              0x04 0x24
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
<72 bytes>

  0x00      0x01      0x03               0x27      0x28  0x48
   ^         ^         ^                  ^         ^     ^
   | ID,LEN  | NONCE   |      DATA        |   pad   | SIG |
   [--------][--------][.................][========][~~~~~]
       |
       |
  [ 01 ...... ]
bits: ID(2)  LEN(6)
```

</blockquote>

Each DATA frame stores a nonce, and while Reading west would verify that the nonce is both sequentially valid such that if any char lies in some sentence, it would not be able to be duplicated or moved around. In this manner, the data is convicted to be authentic despite being signed per individual frame, and any offenders would be identified for the lifetime of the program and rejected at the end.

---

<blockquote>

**End**

```
<72 bytes>

  0x00      0x01      0x03               0x27      0x28  0x48
   ^         ^         ^                  ^         ^     ^
   | ID,LEN  | NONCE   |      DATA        |   pad   | SIG |
   [--------][--------][.................][========][~~~~~]
       |
       |
  [ 11 ...... ]
bits: ID(2)  LEN(6)
```

</blockquote>

This is essentially another dataframe with the leftover data. It will be interpreted as such, except the ID is marked to indicate that this is the case. The bootloader must account for any padding in the data segment. It can also be the case that LEN = 0, and in this case no data shall be written.
