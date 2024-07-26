#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16

int decrypt_aes_cbc(const byte* encrypted_input, word32 input_len, 
                    const byte* key, const byte* iv, 
                    byte* decrypted_output) {
    Aes aes;
    int ret;

    // Initialize AES for decryption
    ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
    if (ret != 0) {
        printf("Error setting AES key: %d\n", ret);
        return ret;
    }

    // decrypt
    ret = wc_AesCbcDecrypt(&aes, decrypted_output, encrypted_input, input_len);
    if (ret != 0) {
        printf("Error decrypting: %d\n", ret);
        return ret;
    }

    return 0; //Success
}