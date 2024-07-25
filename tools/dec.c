#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define ALPHABET_SIZE 26
#define BUFFER_SIZE 1024

const char *MORSE_CODE_DICT[36][2] = {
    {"A", ".-"}, {"B", "-..."}, {"C", "-.-."}, {"D", "-.."}, {"E", "."},
    {"F", "..-."}, {"G", "--."}, {"H", "...."}, {"I", ".."}, {"J", ".---"},
    {"K", "-.-"}, {"L", ".-.."}, {"M", "--"}, {"N", "-."}, {"O", "---"},
    {"P", ".--."}, {"Q", "--.-"}, {"R", ".-."}, {"S", "..."}, {"T", "-"},
    {"U", "..-"}, {"V", "...-"}, {"W", ".--"}, {"X", "-..-"}, {"Y", "-.--"},
    {"Z", "--.."}, {"1", ".----"}, {"2", "..---"}, {"3", "...--"}, {"4", "....-"},
    {"5", "....."}, {"6", "-...."}, {"7", "--..."}, {"8", "---.."}, {"9", "----."},
    {"0", "-----"}, {", ", "--..--"}, {".", ".-.-.-"}, {"?", "..--.."}, {"/", "-..-."},
    {"-", "-....-"}, {"(", "-.--."}, {")", "-.--.-"}
};

char *step2r(const char *s, int key);
char *step3r(const char *s, int key);
char *step4r(const char *s, const char *key);
char *step5r(const char *s);
char *step6r(const char *s, const uint8_t *key, const uint8_t *iv);
char *step7r(const char *s);
char *step8r(const char *s, int l, int r);
char *decryption(char **flags, int flag_count);
char **smartUndoPrint(const char *s, int *count);

char *step2r(const char *s, int key) {
    return strdup(s);
}

char *step3r(const char *s, int key) {
    return strdup(s);
}

char *step4r(const char *s, const char *key) {
    return strdup(s);
}

char *step5r(const char *s) {
    return strdup(s);
}

char *step6r(const char *s, const uint8_t *key, const uint8_t *iv) {
    AES_KEY decryptKey;
    uint8_t decrypted[BUFFER_SIZE];
    int len = strlen(s) / 2;
    uint8_t *input = (uint8_t *)malloc(len);
    
    for (int i = 0; i < len; i++) {
        sscanf(s + 2 * i, "%2hhx", &input[i]);
    }
    
    AES_set_decrypt_key(key, 128, &decryptKey);
    AES_cbc_encrypt(input, decrypted, len, &decryptKey, (uint8_t *)iv, AES_DECRYPT);
    
    free(input);
    return strdup((char *)decrypted);
}

char *step7r(const char *s) {
    return strdup(s);
}

char *step8r(const char *s, int l, int r) {
    return strdup(s);
}

char *decryption(char **flags, int flag_count) {
    return strdup(flags[0]);
}

char **smartUndoPrint(const char *s, int *count) {
    char **lines = malloc(BUFFER_SIZE * sizeof(char *));
    char *token;
    char *str = strdup(s);
    *count = 0;

    token = strtok(str, "\n");
    while (token != NULL) {
        lines[(*count)++] = strdup(token);
        token = strtok(NULL, "\n");
    }

    free(str);
    return lines;
}