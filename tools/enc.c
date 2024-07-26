#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16

int encrypt_aes_cbc(const byte* input, word32 input_len, 
                    const byte* key, const byte* iv, 
                    byte* encrypted_output) {
    Aes aes;
    int ret;

    // Initialize AES for encryption
    ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("Error setting AES key: %d\n", ret);
        return ret;
    }

    // encrypt
    ret = wc_AesCbcEncrypt(&aes, encrypted_output, input, input_len);
    if (ret != 0) {
        printf("Error encrypting: %d\n", ret);
        return ret;
    }

    return 0; //Success
}
