#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <sys/time.h>

OSSL_LIB_CTX *libctx = NULL;
const char *propq = NULL;

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

void encrypt(const char* in, const char* out, unsigned char* key, unsigned char* iv) {
    struct timeval stop, start;
    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");
    unsigned char indata[MAX_FILE_SIZE];
    unsigned char outdata[MAX_FILE_SIZE];
    int bytes_read, bytes_write, tmplen;

    gettimeofday(&start, NULL);
    bytes_read = fread(indata, 1, MAX_FILE_SIZE, ifp);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libctx, "ARIA-128-CBC", propq);
    EVP_EncryptInit_ex2(ctx, cipher, key, iv, /* params */ NULL);
    EVP_EncryptUpdate(ctx, outdata, &bytes_write, indata, bytes_read);
    EVP_EncryptFinal_ex(ctx, outdata + bytes_write, &tmplen);

    fwrite(outdata, 1, bytes_write + tmplen, ofp);

    gettimeofday(&stop, NULL);
    printf("Aria CBC << encrypt >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

void decrypt(const char* in, const char* out, unsigned char* key, unsigned char* iv) {
    struct timeval stop, start;
    FILE *ifp = fopen(in, "r+");
    FILE *ofp = fopen(out, "w+");
    unsigned char indata[MAX_FILE_SIZE];
    unsigned char outdata[MAX_FILE_SIZE];
    int bytes_read, bytes_write, tmplen;

    gettimeofday(&start, NULL);
    bytes_read = fread(indata, 1, MAX_FILE_SIZE, ifp);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libctx, "ARIA-128-CBC", propq);
    EVP_DecryptInit_ex2(ctx, cipher, key, iv, /* params */ NULL);
    EVP_DecryptUpdate(ctx, outdata, &bytes_write, indata, bytes_read);
    EVP_DecryptFinal_ex(ctx, outdata + bytes_write, &tmplen);

    fwrite(outdata, 1, bytes_write + tmplen, ofp);

    gettimeofday(&stop, NULL);
    printf("Aria CBC << decript >> %s -> %s:\t\t %lu microseconds\n", in, out, 
        (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);

    fclose(ifp);
    fclose(ofp);
}

int ariaCbc(void) {
    unsigned char userkey[16]; 
    unsigned char iv[16];

    remove("1k-ari.dat");
    remove("1k-ari-dec.txt");
    remove("10k-ari.dat");
    remove("10k-ari-dec.txt");
    remove("large-binary-ari.dat");
    remove("large-binary-ari-dec.MP4");

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

    encrypt("1k.txt", "1k-ari.dat", userkey, iv);
    decrypt("1k-ari.dat", "1k-ari-dec.txt", userkey, iv);
    encrypt("10k.txt", "10k-ari.dat", userkey, iv);
    decrypt("10k-ari.dat", "10k-ari-dec.txt", userkey, iv);
    encrypt("large-binary.MP4", "large-binary-ari.dat", userkey, iv);
    decrypt("large-binary-ari.dat", "large-binary-ari-dec.MP4", userkey, iv);

    return 0;
}    

int main() {
    if (!ariaCbc()) {
        return -1;
    }

    return 0;
}    