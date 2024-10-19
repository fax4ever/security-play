#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/time.h>

const int MAX_FILE_SIZE = 2000000;

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
    unsigned char indata[MAX_FILE_SIZE];
    unsigned char outdata[MAX_FILE_SIZE];
    int bytes_read, bytes_write;

    gettimeofday(&start, NULL);
    // for fairness we include in the time also the read / write of the file

    unsigned char ivec[AES_BLOCK_SIZE];
    memcpy(ivec, iv, AES_BLOCK_SIZE);
    bytes_read = fread(indata, 1, MAX_FILE_SIZE, ifp);
    AES_cbc_encrypt(indata, outdata, bytes_read, &key, ivec, AES_ENCRYPT);
    bytes_write = fwrite(outdata, 1, bytes_read, ofp);

    gettimeofday(&stop, NULL);
    printf("AES CBC << encrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

void decryptAES(const char* in, const char* out, AES_KEY key, unsigned char* iv) {
    struct timeval stop, start;
    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");
    unsigned char indata[MAX_FILE_SIZE];
    unsigned char outdata[MAX_FILE_SIZE];
    int bytes_read, bytes_write;

    gettimeofday(&start, NULL);
    // for fairness we include in the time also the read / write of the file

    unsigned char ivec[AES_BLOCK_SIZE];
    memcpy(ivec, iv, AES_BLOCK_SIZE);
    bytes_read = fread(indata, 1, MAX_FILE_SIZE, ifp);
    AES_cbc_encrypt(indata, outdata, bytes_read, &key, ivec, AES_DECRYPT);
    bytes_write = fwrite(outdata, 1, bytes_read, ofp);

    gettimeofday(&stop, NULL);
    printf("AES CBC << decrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

int aesCbc(void) {
    unsigned char userkey[16]; 
    unsigned char iv[16];

    remove("1k-cbc.dat");
    remove("1k-cbc-dec.txt");
    remove("10k-cbc.dat");
    remove("10k-cbc-dec.txt");
    remove("large-binary-cbc.dat");
    remove("large-binary-cbc-dec.MP4");

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

    encryptAES("1k.txt", "1k-cbc.dat", key, iv);
    decryptAES("1k-cbc.dat", "1k-cbc-dec.txt", key, iv);
    encryptAES("10k.txt", "10k-cbc.dat", key, iv);
    decryptAES("10k-cbc.dat", "10k-cbc-dec.txt", key, iv);
    encryptAES("large-binary.MP4", "large-binary-cbc.dat", key, iv);
    decryptAES("large-binary-cbc.dat", "large-binary-cbc-dec.MP4", key, iv);

    return 0;
}

int main() {
    if (!aesCbc()) {
        return -1;
    }

    return 0;
}    