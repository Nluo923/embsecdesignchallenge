// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"

// oi oi oi
#include "frame.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
uint32_t random(uint8_t state);
int frame_unpack_begin(uint8_t *, BeginFrame *);
int frame_unpack_message(uint8_t *, MessageFrame *);
int frame_unpack_data(uint8_t *, DataFrame *);

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

// Encryption Constants
#define HMAC_KEY_LENGTH 48
#define HMAC_SIG_LENGTH 48
#define AES_KEY_LENGTH 16
#define AES_IV_LENGTH 16
#define AES_GCM_TAG_LENGTH 16
#define AES_GCM_AAD_LENGTH 16

// Firmware v2 is embedded in bootloader
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Current (as in the one to be updated) device metadata
uint16_t * fw_version_address = (uint16_t *) (METADATA_BASE);
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Encryption
// char HMAC_KEY[HMAC_KEY_LENGTH] = HMAC;
// char AES_KEY [AES_KEY_LENGTH]  = KEY;
// char IV      [AES_IV_LENGTH]   = INIT_IV;
// char AES_AAD [AES_GCM_AAD_LENGTH] = AAD;

// mulberry32 - an actual high quality 32-bit generator
uint32_t random(uint8_t state) {
    uint32_t z = state + 0x6D2B79F5;
    z = (z ^ z >> 15) * (1 | z);
    z ^= z + (z ^ z >> 7) * (61 | z);
    return z ^ z >> 14;
}

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}


int main(void) {

    // // Initialize UART channels
    // // 0: Reset
    // // 1: Host Connection
    // // 2: Debug
    // uart_init(UART0);
    // uart_init(UART1);
    // uart_init(UART2);

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    //the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}


 /*
 * Load the firmware into flash.
 */
void load_firmware(void) {
    int frame_length = 0;
    int read_success = 0; // The LSB is set by uart_read if successful, but is always 1 when BLOCKING.
    uint32_t uart_receive = 0;

    // Get version.
    uint32_t version = 0;
    uart_receive = uart_read(UART0, BLOCKING, &read_success);
    version = (uint32_t)uart_receive;
    uart_receive = uart_read(UART0, BLOCKING, &read_success);
    version |= (uint32_t)uart_receive << 8;

    // Get size.
    uint32_t size = 0;
    uart_receive = uart_read(UART0, BLOCKING, &read_success);
    size = (uint32_t)uart_receive;
    uart_receive = uart_read(UART0, BLOCKING, &read_success);
    size |= (uint32_t)uart_receive << 8;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), set as version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }

    if (version != 0 && version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);

    uart_write(UART0, OK); // Acknowledge the metadata.

    /* Loop here until you can get all your characters and stuff */
    uint32_t data_index = 0;
    uint32_t page_addr = FW_BASE;

    while (1) {

        // Get two bytes for the length.
        uart_receive = uart_read(UART0, BLOCKING, &read_success);
        frame_length = (int)uart_receive << 8;
        uart_receive = uart_read(UART0, BLOCKING, &read_success);
        frame_length += (int)uart_receive;

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i) {
            data[data_index] = uart_read(UART0, BLOCKING, &read_success);
            data_index += 1;
        } // for

        // If we filed our page buffer, program it
        if (data_index == FLASH_PAGESIZE || frame_length == 0) {
            // Try to write flash and check for error
            if (program_flash((uint8_t *) page_addr, data, data_index)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            data_index = 0;

            // If at end of firmware, go to main
            if (frame_length == 0) {
                uart_write(UART0, OK);
                break;
            }
        } // if

        uart_write(UART0, OK); // Acknowledge the frame.
    } // while(1)
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}

void boot_firmware(void) {
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART0, (char *)fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}

// jon take a look at this
int sha_hmac384(const unsigned char* key, int key_len, const unsigned char* data, int data_len, unsigned char* out) {
    Hmac hmac;
    int ret;

    // Initialize HMAC context
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret; // Return error code if initialization fails
    }

    // Set HMAC key and hash type
    ret = wc_HmacSetKey(&hmac, WC_SHA384, key, key_len);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return ret; // Return error code if setting key fails
    }

    // Update HMAC with data
    ret = wc_HmacUpdate(&hmac, data, data_len);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return ret; // Return error code if update fails
    }

    // Finalize HMAC and retrieve output
    ret = wc_HmacFinal(&hmac, out);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return ret; // Return error code if finalization fails
    }

    // Free HMAC context
    wc_HmacFree(&hmac);

    return 48; // Return the length of the output for SHA-384 HMAC
}

// Determine which frame read to utilize
void frame_read() {

}

/*
 * Takes FRAME_SIZE bytes, and pointer to the corresponding struct to write to.
 * Returns 0 on success
 */

int frame_unpack_begin(uint8_t* bytes, BeginFrame* frame) {
    if ((bytes[0] >> 6) != 0) return -1;

    frame->version = bytes[1];
    frame->num_packets = (bytes[3] << 8) | bytes[2];
    
    for (int i=0; i<32; i++) {
        frame->signature[i] = bytes[4+i];
    }

    return 0;
}

int frame_unpack_message(uint8_t* bytes, MessageFrame* frame) {
    if ((bytes[0] >> 6) != 1) return -1;

    for (int i=0; i<82; i++) {
        frame->terminated_message[i] = bytes[1+i];
    }

    frame->terminated_message[82] = '\0';

    return 0;
}

int frame_unpack_data(uint8_t* bytes, DataFrame* frame) {
    // Reject if first bit unset
    if (!(bytes[0] & 0b10000000)) return -1;

    frame->len = bytes[0] & 0b00111111;
    frame->nonce = (bytes[2] << 8) | bytes[1];

    for (int i=0; i<48; i++) {
        frame->data[i] = (i < frame->len) ? bytes[3+i] : 0x00;
    }

    for (int i=0; i<32; i++) {
        frame->signature[i] = bytes[52+i];
    }

    return 0;
}