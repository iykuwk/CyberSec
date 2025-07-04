#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_LEN 1024

// -------- RC4 Context Structure --------
typedef struct {
    unsigned int i;
    unsigned int j;
    unsigned char s[256];
} Rc4Context;

// -------- RC4 Key Scheduling Algorithm --------
void rc4Init(Rc4Context* context, const unsigned char* key, size_t length) {
    unsigned int i, j = 0;
    unsigned char temp;

    // Check parameters
    if (context == NULL || key == NULL || length == 0)
        return;

    // Initialize indices
    context->i = 0;
    context->j = 0;

    // Fill/ initializes S array with identity permutation
    for (i = 0; i < 256; i++) {
        context->s[i] = (unsigned char)i;
    }

    // Scramble S using the key and being processed for 256 iterations
    for (i = 0; i < 256; i++) {
        //Randomising the permutations using suppied key 
        j = (j + context->s[i] + key[i % length]) % 256;
        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }
}

// -------- RC4 Stream Cipher --------
void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char temp, k;
    unsigned char* s = context->s;

    while (length--) {
        //Adjusts the indices for being divible by 256
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        // Swap values of i and j
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        // Generate keystream byte and XOR
        k = s[(s[i] + s[j]) % 256];
        *output++ = *input++ ^ k;
    }

    // Save context
    context->i = i;
    context->j = j;
}

int main() {
    char inputText[MAX_INPUT_LEN];

    // Asks user for input
    printf("Enter message to encrypt: ");
    fgets(inputText, MAX_INPUT_LEN, stdin);

    // Remove newline
    size_t inputLen = strlen(inputText);
    if (inputText[inputLen - 1] == '\n') {
        inputText[inputLen - 1] = '\0';
        inputLen--;
    }

    // RC4 key
    unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    // Initialize context and encrypt
    Rc4Context ctx;
    rc4Init(&ctx, key, sizeof(key));

    unsigned char* ciphertext = (unsigned char*)malloc(inputLen);
    ZeroMemory(ciphertext, inputLen);
    rc4Cipher(&ctx, (unsigned char*)inputText, ciphertext, inputLen);

    printf("\nEncrypted Hex Output:\n");
    for (size_t i = 0; i < inputLen; i++) {
        printf("%02X ", ciphertext[i]);
    }

    // Decryption phase
    printf("\n\nPress Enter to decrypt...");
    getchar();

    rc4Init(&ctx, key, sizeof(key)); // Reinitialize before decrypting
    unsigned char* plaintext = (unsigned char*)malloc(inputLen + 1);
    ZeroMemory(plaintext, inputLen + 1);
    rc4Cipher(&ctx, ciphertext, plaintext, inputLen);

    printf("\nDecrypted Text:\n%s\n", plaintext);

    // Cleanup
    free(ciphertext);
    free(plaintext);

    printf("\nPress Enter to quit...");
    getchar();
    return 0;
}
