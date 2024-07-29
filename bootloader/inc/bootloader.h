// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define IV_LEN 16
#define MAX_MSG_LEN 256

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Data buffer sizes
#define META_LEN 22 // Excludes message bytes
#define IV_LEN 16
#define MAX_MSG_LEN 256
#define BLOCK_SIZE FLASH_PAGESIZE
#define SIG_SIZE 256
#define CHUNK_SIZE (BLOCK_SIZE + SIG_SIZE)

#define MAX_CHUNK_NO 32 // 30KB firmware + padding

// Return messages
#define VERIFY_SUCCESS 0
#define VERIFY_ERR 1

#define FW_LOADED 0
#define FW_ERROR 1

// Encryption Constants
#define HMAC_KEY_LENGTH 48
#define HMAC_SIG_LENGTH 32
#define AES_KEY_LENGTH 16
#define AES_IV_LENGTH 16
#define AES_GCM_TAG_LENGTH 16
#define AES_GCM_AAD_LENGTH 16

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash
#define MAX_FIRMWARE_SIZE 30720 // 30 Kibibytes
#define MAX_FIRMWAREBLOB_SIZE 31792 // 30 Kibibyte FW + 1 KB Release Message + 48 byte HMAC Signature

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Frame Constants
#define SETUP   0
#define DATA    1
#define AUTH    2
#define VERSION 3
#define DATA_DELIM_SIZE 62

#define FRAME_SIZE 84
#define PADDED_FRAME_SIZE 96
#define ENCRYPTED_FRAME_SIZE 96

typedef struct fw_meta_s {
    uint16_t    ver;                // Version of current fw being loaded
    uint16_t    min_ver;            // Miniumum fw version (not updated when debug fw loaded) 
    uint16_t    chunks;             // Length of fw in 1kb chunks
    uint16_t    msgLen;             // Length of fw message in bytes
    uint8_t     msg[MAX_MSG_LEN];   // fw release message
} fw_meta_st;

long program_flash(void* page_addr, unsigned char * data, unsigned int data_len);

#endif

