#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/time.h>

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
    struct timeval stop, start;

    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");

    unsigned char indata[AES_BLOCK_SIZE];
    unsigned char outdata[AES_BLOCK_SIZE];

    int postion = 0;
    int bytes_read, bytes_write;

    gettimeofday(&start, NULL);

    while (1) {
        unsigned char ivec[AES_BLOCK_SIZE];
        memcpy(ivec, iv, AES_BLOCK_SIZE);
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);
        AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &postion, AES_ENCRYPT);
        bytes_write = fwrite(outdata, 1, bytes_read, ofp);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }

    gettimeofday(&stop, NULL);
    printf("AES CFB 128 << encrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

void decryptAES(const char* in, const char* out, AES_KEY key, unsigned char* iv) {
    struct timeval stop, start;

    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");

    unsigned char outdata[AES_BLOCK_SIZE];
    unsigned char decryptdata[AES_BLOCK_SIZE];

    int postion = 0;
    int bytes_read, bytes_write;

    gettimeofday(&start, NULL);

    while (1) {
        unsigned char ivec[AES_BLOCK_SIZE];
        memcpy(ivec, iv, AES_BLOCK_SIZE);
        bytes_read = fread(outdata, 1, AES_BLOCK_SIZE, ifp);
        AES_cfb128_encrypt(outdata, decryptdata, bytes_read, &key, ivec, &postion, AES_DECRYPT);
        bytes_write = fwrite(decryptdata, 1, bytes_read, ofp);
        if (bytes_read < AES_BLOCK_SIZE)
            break;
    }

    gettimeofday(&stop, NULL);
    printf("AES CFB 128 << decrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

int aesCbf(void) {
    unsigned char userkey[16]; 
    unsigned char iv[16];

    remove("1k-aes.dat");
    remove("1k-aes-dec.txt");
    remove("10k-aes.dat");
    remove("10k-aes-dec.txt");
    remove("large-binary-aes.dat");
    remove("large-binary-aes-dec.MP4");

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
    encryptAES("10k.txt", "10k-aes.dat", key, iv);
    decryptAES("10k-aes.dat", "10k-aes-dec.txt", key, iv);
    encryptAES("large-binary.MP4", "large-binary-aes.dat", key, iv);
    decryptAES("large-binary-aes.dat", "large-binary-aes-dec.MP4", key, iv);

    return 0;
}

int main() {
    if (!aesCbf()) {
        return -1;
    }

    return 0;
}