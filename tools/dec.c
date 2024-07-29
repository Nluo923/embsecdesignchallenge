#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16
#define TEXT_LENGTH 84

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

    // Decrypt
    ret = wc_AesCbcDecrypt(&aes, decrypted_output, encrypted_input, input_len);
    if (ret != 0) {
        printf("Error decrypting: %d\n", ret);
        return ret;
    }

    return 0; // Success
}

int caesar_decrypt(char *ciphertext, int shift, char *decrypted) {
    int i;
    char ch;
    // Iterate through characters
    for (i = 0; i < TEXT_LENGTH; ++i) {
        ch = ciphertext[i];
        // Uppercase
        if (ch >= 'A' && ch <= 'Z') {
            ch = ((ch - 'A' - shift + 26) % 26) + 'A';
            decrypted[i] = ch;
        }
        // Lowercase
        else if (ch >= 'a' && ch <= 'z') {
            ch = ((ch - 'a' - shift + 26) % 26) + 'a';
            decrypted[i] = ch;
        }
        // Anything else
        else {
            decrypted[i] = ch;
        }
    }

    return 0;

    // does not include null terminator since we're assuming its all the same length
    // decrypted[TEXT_LENGTH] = '\0';
}