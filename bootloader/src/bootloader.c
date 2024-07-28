// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"
#include "keys.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/hw_flash.h"
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
int verify_signature(uint8_t * signature, uint8_t * data, int data_len);
void read_frame(uint8_t* bytes);
int frame_unpack_begin(uint8_t *, BeginFrame *);
int frame_unpack_message(uint8_t *, MessageFrame *);
int frame_unpack_data(uint8_t *, DataFrame *);

// Firmware v2 is embedded in bootloader
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Current (as in the one to be updated) device metadata
uint16_t * fw_version_address = (uint16_t *) (METADATA_BASE);
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t * fw_release_message_address = (uint8_t *)(METADATA_BASE + 4);

#define MAX_INTERMEDIATE_PAGES 4
// Intermediate Firmware Buffer
// These staging buffers store incoming firmware until fully verified and then flashed.
uint8_t itm_data[FLASH_PAGESIZE * MAX_INTERMEDIATE_PAGES];
int itm_start_idx = 0; // Frame index

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

// "Error codes"
#define UNPACK_ERR -1
#define WRONG_VERSION_ERR -2
#define WRONG_BYTESIZE_ERR -3
#define BAD_SIGNATURE_ERR -4
#define TOO_MANY_FRAMES_ERR -5
#define VERY_BAD_ERR -6
#define INVALID_HASH_ERR -10
#define BLINK_ON_CRASH 1

void led_on(uint8_t red, uint8_t green, uint8_t blue) {
    if (red) GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1);
    if (green) GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);
    if (blue) GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2);
}

void led_off() {
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3, 0x0);
}

void led_blink(uint8_t red, uint8_t green, uint8_t blue) {
    led_on(red, green, blue);
    SysCtlDelay(SysCtlClockGet() * 0.2);
    led_off();
    SysCtlDelay(SysCtlClockGet() * 0.2);
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

void disable_debugging(void){
    // Write the unlock value to the flash memory protection registers
    HWREG(FLASH_FMPRE0) = 0xFFFFFFFF;
    HWREG(FLASH_FMPPE0) = 0xFFFFFFFF;

    // Disable the debug interface by writing to the FMD and FMC registers
    HWREG(FLASH_FMD) = 0xA4420004;
    HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;
}

void kill_bootloader(int8_t err) {
    while (err++ && BLINK_ON_CRASH) led_blink(1, 1, 1);
    uart_write(UART0, ERROR);
    SysCtlReset();
}

int main(void) {
    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    //the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3);

    // debug_delay_led();

    initialize_uarts(UART0);
    // disable_debugging();

    // uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    // uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        led_blink(0, 1, 0);

        if (instruction == UPDATE) {
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
    uart_write_str(UART0, "U");

    int unpack_fail = -1;
    uint8_t raw_frame[FRAME_SIZE];
    
    // Get metadata
    BeginFrame metadata;
    led_on(0, 0, 1);
    read_frame(raw_frame);
    unpack_fail = frame_unpack_begin(raw_frame, &metadata);

    if (unpack_fail != 0) {
        kill_bootloader(UNPACK_ERR);
        return;
    }

    // Compare to old version and kill_bootloader if older (note special case for version 0).
    // If no metadata available (0xFFFF), set as version 1
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 1;
    }
    if (metadata.version != 0 && metadata.version < old_version) {
        kill_bootloader(WRONG_VERSION_ERR);
        return;
    }
    if (metadata.bytesize > MAX_FIRMWARE_SIZE) {
        kill_bootloader(WRONG_BYTESIZE_ERR);
        return;
    }
    if (metadata.version == 0) {
        metadata.version = old_version; // If debug firmware, don't change version
    }

    // Signed by concat [version, num_packets, bytesize] in that order
    // Yeah i could read from a position in the struct but surely we have 6 bytes to spare
    uint8_t concat_metadata[5];
    memcpy(concat_metadata, &metadata.version, 1);
    memcpy(1 + concat_metadata, (uint8_t *) &metadata.num_packets, 2);
    memcpy(3 + concat_metadata, (uint8_t *) &metadata.bytesize, 2);
    int metadata_sign_res = verify_signature(metadata.signature, concat_metadata, sizeof(concat_metadata));
    if (metadata_sign_res != 0) {
        kill_bootloader(metadata_sign_res);
        return;
    }

    led_off();

    uart_write(UART0, OK); // Acknowledge the metadata.

    // Release Message
    MessageFrame release_message;
    read_frame(raw_frame);
    unpack_fail = frame_unpack_message(raw_frame, &release_message);
    if (unpack_fail) {
        kill_bootloader(UNPACK_ERR);
        return;
    }
    uart_write(UART0, OK); // Do not ghost the sender.
    
    led_on(0, 0, 1);
    // Read dataframes and store in intermediate buffer
    int expected_nonce = 0;
    int frames_received = 0;
    int real_bytesize = 0;
    while (1) {
        // If exceeds expected frames, kill_bootloader
        if (frames_received >= metadata.num_packets) { // POOPOO
            kill_bootloader(TOO_MANY_FRAMES_ERR);
            return;
        }

        // Read in a frame
        read_frame(raw_frame);
        frames_received++;

        // Unpack as DataFrame
        DataFrame data_frame;
        unpack_fail = frame_unpack_data(raw_frame, &data_frame);
        real_bytesize += data_frame.len;

        // Explode if bad, out of order/duped, or exceeds bytesize
        if (unpack_fail != 0 || data_frame.nonce != expected_nonce || real_bytesize > metadata.bytesize || real_bytesize > MAX_FIRMWARE_SIZE) {
            kill_bootloader(VERY_BAD_ERR);
            return;
        }

        // Verify signature
        uint8_t concat_data[50];
        memcpy(concat_data, (uint8_t *) &data_frame.nonce, 2);
        memcpy(2+concat_data, &data_frame.data, 48);
        int sig_res = verify_signature(data_frame.signature, concat_data, 50);
        if (sig_res != 0) {
            kill_bootloader(sig_res);
            return;
        }

        uart_write(UART0, OK); // Acknowledge the frame.

        // Save to intermediate buffer since it seems all right.
        memcpy(&itm_data[itm_start_idx], &data_frame.data, 48 * sizeof(uint8_t)); // Copy the 48 firmware bytes
        itm_start_idx += sizeof(data_frame.data); // Bump the itm buffer pointer

        expected_nonce++;

        // If is End frame, stop expecting dataframes.
        if (data_frame.is_last_frame) break;
    }

    // Verification of payload
    if (real_bytesize != metadata.bytesize || frames_received != metadata.num_packets) {
        kill_bootloader(TOO_MANY_FRAMES_ERR);
        return;
    }

    led_off();

    // -------------------------------
    // Beyond this point, saul goodman
    // -------------------------------

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata_to_write = ((metadata.bytesize & 0xFFFF) << 16) | (metadata.version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata_to_write), 4);

    // Write message to Flash
    program_flash(fw_release_message_address, (uint8_t *)(&release_message.terminated_message), 83);

    uint32_t itm_ptr = 0;
    uint32_t page_addr = FW_BASE;
    while (itm_ptr < itm_start_idx) { // Ensure that the flash pointer doesn't exceed 
        if (program_flash((uint8_t *) page_addr, &itm_data[itm_ptr], FLASH_PAGESIZE) != 0) {
            kill_bootloader(WRONG_BYTESIZE_ERR);
            return;
        }

        itm_ptr += FLASH_PAGESIZE;
        page_addr += FLASH_PAGESIZE; // Move to next page
    }

    uart_write(UART0, OK);
    led_blink(0, 1, 0);
    led_blink(0, 1, 0);
    led_blink(0, 1, 0);
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

// Verify signature using a given signature and verify by hashing the data.
int verify_signature(uint8_t * signature, uint8_t * data, int data_len) {
    Hmac hmac;
    int hmac_res;

    hmac_res = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (hmac_res != 0) return INVALID_HASH_ERR;
    hmac_res = wc_HmacSetKey(&hmac, WC_SHA256, HMAC_KEY, sizeof(HMAC_KEY));
    if (hmac_res != 0) return INVALID_HASH_ERR; 
    hmac_res = wc_HmacUpdate(&hmac, data, data_len);
    if (hmac_res != 0) return INVALID_HASH_ERR; 

    uint8_t hash[HMAC_SIG_LENGTH];
    hmac_res = wc_HmacFinal(&hmac, (uint8_t *) &hash);
    if (hmac_res != 0) return INVALID_HASH_ERR; 

    int res = 0;
    for (int i = 0; i < HMAC_SIG_LENGTH; i++) {
        res |= hash[i] ^ signature[i];
    };

    if (res != 0) return BAD_SIGNATURE_ERR;

    return 0;
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

// Reads FRAME
void read_frame(uint8_t* bytes) {
    int suck;
    for (int i=0; i<FRAME_SIZE; i++) {
        bytes[i] = uart_read(UART0, 1, &suck);
    }
}

/*
 * Unpacking takes a buffer of FRAME_SIZE bytes, and pointer to the corresponding struct to populate.
 * Returns 0 on success
 */

// Populate a BeginFrame
int frame_unpack_begin(uint8_t* bytes, BeginFrame* frame) {
    if ((bytes[0] >> 6) != 0) return -1;

    frame->version = bytes[1];
    frame->num_packets = (bytes[3] << 8) | bytes[2];
    frame->bytesize = (bytes[5] << 8) | bytes[4];
    
    for (int i=0; i<HMAC_SIG_LENGTH; i++) {
        frame->signature[i] = bytes[6+i];
    }

    return 0;
}

// Populate a MessageFrame
int frame_unpack_message(uint8_t* bytes, MessageFrame* frame) {
    if ((bytes[0] >> 6) != 1) return -1;

    for (int i=0; i<82; i++) {
        frame->terminated_message[i] = bytes[1+i];
    }

    frame->terminated_message[82] = '\0';

    return 0;
}

// Populate a DataFrame
int frame_unpack_data(uint8_t* bytes, DataFrame* frame) {
    uint8_t id = bytes[0] & 0b11000000;
    // Reject if first bit unset
    if (!(bytes[0] & 0b10000000)) return -1;

    frame->is_last_frame = id == 0b11000000;

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