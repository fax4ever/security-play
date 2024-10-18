#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void print_data(const char* title, const void* data, int len) {
    printf("%s : ", title);

    const unsigned char* p = (const unsigned char*) data;
    int i = 0;
    for (; i<len; ++i) {
        printf("%02X ", *p++);
    }

    printf("\n");
}

void encryptAES(const char* in, const char* out, AES_KEY key, unsigned char* iv) {
    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];

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

void decryptAES(const char* in, const char* out, AES_KEY key, unsigned char* iv) {
    FILE *ifp, *ofp;
    ifp = fopen(in, "r+");
    ofp = fopen(out, "w+");

    unsigned char outdata[AES_BLOCK_SIZE];
    unsigned char decryptdata[AES_BLOCK_SIZE];

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
    unsigned char userkey[16]; 
    unsigned char iv[16];

    remove("1k-aes.dat");
    remove("1k-aes-dec.txt");

    if (!RAND_bytes(userkey, sizeof userkey)) {
        printf("Error initializing the secret key");
        return -1;
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error initializing the initialization vector");
        return -1;
    }

    AES_KEY key;

    print_data("The key", userkey, sizeof userkey);
    print_data("The IV ", iv, sizeof iv);
    AES_set_encrypt_key(userkey, 128, &key);

    encryptAES("1k.txt", "1k-aes.dat", key, iv);
    decryptAES("1k-aes.dat", "1k-aes-dec.txt", key, iv);

    return 0;
}
