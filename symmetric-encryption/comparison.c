#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

int main() {
    // 16 * 8 => 128 bit each:
    unsigned char key[16], iv[16]; 

    if (!RAND_bytes(key, sizeof key)) {
        printf("Error initializing the secret key");
        return -1;
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error initializing the initialization vector");
        return -1;
    }

    printf("The key: '%s'\n", key);
    printf("The IV: '%s'\n", iv);

    return 0;
}    
    