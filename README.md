# Joint Algorithm Yielding Data Encryption Network (JAYDEN)

---

## Project Structure

```
.
├── bootloader
│  ├── bin
│  │  └── bootloader.bin
│  ├── src
│  │  ├── bootloader.c
│  │  └── startup_gcc.c
│  ├── Makefile
│  ├── secret_build_output.txt
├── firmware
│  ├── bin
│  │  └── firmware.bin
│  ├── src
│  │  └── firmware.c
│  ├── lib
│  └── Makefile
├── lib
│  ├── driverlib
│  ├── inc
│  └── uart
├── SPECIFICATIONS.md
└── tools
   ├── bl_build.py
   ├── firmware_protected.bin
   ├── fw_protect.py
   ├── fw_update.py
   └── util.py
```

---

# Build Steps

```
cd firmware && make firmware && cd ..
cd tools

python3 bl_build.py && lm4flash ../bootloader/bin/bootloader.bin
python3 fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Massage"

# if using ttyACM0
python3 fw_update.py --firmware ./firmware_protected.bin

# if otherwise
python3 fw_update.py --firmware ./firmware_protected.bin --devname <device name without /dev/>

# access firmware
picocom -b 115200 /dev/ttyACM0
```
