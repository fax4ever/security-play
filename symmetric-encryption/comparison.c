#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// 16 * 8 => 128 bit each:
unsigned char key[16], iv[16]; 

void print_data(const char *title, const void* data, int len) {
    printf("%s : ", title);

    const unsigned char * p = (const unsigned char *) data;
    int i = 0;
    for (; i<len; ++i) {
        printf("%02X ", *p++);
    }

    printf("\n");
}

int main() {
    if (!RAND_bytes(key, sizeof key)) {
        printf("Error initializing the secret key");
        return -1;
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error initializing the initialization vector");
        return -1;
    }

    print_data("The key", key, sizeof(key));
    print_data("The IV ", iv, sizeof(iv));

    return 0;
}
