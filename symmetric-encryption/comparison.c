#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// 16 * 8 => 128 bit each:
unsigned char userkey[16], iv[16];
unsigned char indata[AES_BLOCK_SIZE];
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char decryptdata[AES_BLOCK_SIZE];
AES_KEY key;

void print_data(const char* title, const void* data, int len) {
    printf("%s : ", title);

    const unsigned char* p = (const unsigned char*) data;
    int i = 0;
    for (; i<len; ++i) {
        printf("%02X ", *p++);
    }

    printf("\n");
}

void encrypt(void) {
    FILE *ifp = fopen("1k.txt", "r+");
    FILE *ofp = fopen("1k-aes.dat", "w+");

    int postion = 0;
    int bytes_read, bytes_write;

    while (1) {
        unsigned char ivec[AES_BLOCK_SIZE];
        memcpy(ivec, iv, AES_BLOCK_SIZE);
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);
        AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &postion, AES_ENCRYPT);
        bytes_write = fwrite(outdata, 1, bytes_read, ofp);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }

    fclose(ifp);
    fclose(ofp);
}

void decrypt(void) {
    FILE *ifp, *ofp;
    ifp = fopen("1k-aes.dat", "r+");
    ofp = fopen("1k-aes-dec.txt", "w+");
    int postion = 0;
    int bytes_read, bytes_write;

    while (1) {
        unsigned char ivec[AES_BLOCK_SIZE];
        memcpy(ivec, iv, AES_BLOCK_SIZE);
        bytes_read = fread(outdata, 1, AES_BLOCK_SIZE, ifp);
        AES_cfb128_encrypt(outdata, decryptdata, bytes_read, &key, ivec, &postion, AES_DECRYPT);
        bytes_write = fwrite(decryptdata, 1, bytes_read, ofp);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }
    
    fclose(ifp);
    fclose(ofp);
}

int main() {
    if (!RAND_bytes(userkey, sizeof userkey)) {
        printf("Error initializing the secret key");
        return -1;
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error initializing the initialization vector");
        return -1;
    }

    print_data("The key", userkey, sizeof userkey);
    print_data("The IV ", iv, sizeof iv);
    AES_set_encrypt_key(userkey, 128, &key);

    encrypt();
    decrypt();

    return 0;
}
