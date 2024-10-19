#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/camellia.h>
#include <openssl/rand.h>
#include <sys/time.h>

// we know that we're going to handle files at most of 4MB
const int MAX_FILE_SIZE = 4000000;

void print_data(const char* title, const void* data, int len) {
    printf("%s : ", title);

    const unsigned char* p = (const unsigned char*) data;
    int i = 0;
    for (; i<len; ++i) {
        printf("%02X ", *p++);
    }

    printf("\n");
}

void encrypt(const char* in, const char* out, CAMELLIA_KEY key, unsigned char* iv) {
    struct timeval stop, start;
    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");
    unsigned char indata[MAX_FILE_SIZE];
    unsigned char outdata[MAX_FILE_SIZE];
    int bytes_read, bytes_write;

    gettimeofday(&start, NULL);
    // for fairness we include in the time also the read / write of the file

    unsigned char ivec[CAMELLIA_BLOCK_SIZE];
    memcpy(ivec, iv, CAMELLIA_BLOCK_SIZE);
    bytes_read = fread(indata, 1, MAX_FILE_SIZE, ifp);
    Camellia_cbc_encrypt(indata, outdata, bytes_read, &key, ivec, CAMELLIA_ENCRYPT);
    bytes_write = fwrite(outdata, 1, bytes_read, ofp);

    gettimeofday(&stop, NULL);
    printf("Camellia CBC << encrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

void decrypt(const char* in, const char* out, CAMELLIA_KEY key, unsigned char* iv) {
    struct timeval stop, start;
    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");
    unsigned char indata[MAX_FILE_SIZE];
    unsigned char outdata[MAX_FILE_SIZE];
    int bytes_read, bytes_write;

    gettimeofday(&start, NULL);
    // for fairness we include in the time also the read / write of the file

    unsigned char ivec[CAMELLIA_BLOCK_SIZE];
    memcpy(ivec, iv, CAMELLIA_BLOCK_SIZE);
    bytes_read = fread(indata, 1, MAX_FILE_SIZE, ifp);
    Camellia_cbc_encrypt(indata, outdata, bytes_read, &key, ivec, CAMELLIA_DECRYPT);
    bytes_write = fwrite(outdata, 1, bytes_read, ofp);

    gettimeofday(&stop, NULL);
    printf("Camellia CBC << decrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

int camelliaCbc(void) {
    unsigned char userkey[16]; 
    unsigned char iv[16];

    remove("1k-cam.dat");
    remove("1k-cam-dec.txt");
    remove("10k-cam.dat");
    remove("10k-cam-dec.txt");
    remove("large-binary-cam.dat");
    remove("large-binary-cam-dec.MP4");

    if (!RAND_bytes(userkey, sizeof userkey)) {
        printf("Error initializing the secret key");
        return -1;
    }
    if (!RAND_bytes(iv, sizeof iv)) {
        printf("Error initializing the initialization vector");
        return -1;
    }

    CAMELLIA_KEY encKey;
    CAMELLIA_KEY decKey;

    print_data("The key", userkey, sizeof userkey);
    print_data("The IV ", iv, sizeof iv);
    Camellia_set_key(userkey, 128, &encKey);
    Camellia_set_key(userkey, 128, &decKey);

    encrypt("1k.txt", "1k-cam.dat", encKey, iv);
    decrypt("1k-cam.dat", "1k-cam-dec.txt", decKey, iv);
    encrypt("10k.txt", "10k-cam.dat", encKey, iv);
    decrypt("10k-cam.dat", "10k-cam-dec.txt", decKey, iv);
    encrypt("large-binary.MP4", "large-binary-cam.dat", encKey, iv);
    decrypt("large-binary-cam.dat", "large-binary-cam-dec.MP4", decKey, iv);

    return 0;
}

int main() {
    if (!camelliaCbc()) {
        return -1;
    }

    return 0;
}    