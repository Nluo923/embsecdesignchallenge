#ifndef FRAME_H
#define FRAME_H

#ifndef BOOTLOADER_H
#include <bootloader.h>
#endif

// Types for frames that will be the *unencrypted* version of incoming data.
// These should not be indexed; utilize their members.
typedef struct begin_frame_t {
    uint8_t version;
    uint16_t num_packets;
    uint16_t bytesize;
    uint8_t signature[32];
} BeginFrame;

typedef struct message_frame_t {
    unsigned char terminated_message[83];
} MessageFrame;

typedef struct data_frame_t {
    uint8_t len; // This will be the six least significant bits of the first incoming byte.
    uint16_t nonce;
    uint8_t data[48];
    uint8_t signature[32];
} DataFrame;

#endif