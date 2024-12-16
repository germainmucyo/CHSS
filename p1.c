#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>   // For random number generation
#include "kyber512.h"      // Include the Kyber512 header

static __inline__ uint64_t timer_start(void) {
    unsigned cycles_low, cycles_high;
    asm volatile("CPUID\n\t"
                 "RDTSC\n\t"
                 "mov %%edx, %0\n\t"
                 "mov %%eax, %1\n\t"
                 : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
}

static __inline__ uint64_t timer_stop(void) {
    unsigned cycles_low, cycles_high;
    asm volatile("RDTSCP\n\t"
                 "mov %%edx, %0\n\t"
                 "mov %%eax, %1\n\t"
                 "CPUID\n\t"
                 : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
}

void aes_perf() {
    int i;
    uint64_t t1, t2;
    uint64_t timearray[1000000];

    unsigned char key[16] = "0123456789abcdef";  // 16-byte key for AES-128
    unsigned char plaintext[16] = "SecretMessage123";  // 16-byte plaintext
    unsigned char ciphertext[16];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    for(i = 0; i < 1000000; i++) {
        t1 = timer_start();
        int len;
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        t2 = timer_stop();
        timearray[i] = t2 - t1;
    }

    FILE *file = fopen("aes.txt", "w");
    if (file) {
        for (int j = 0; j < 1000000; j++) {
            fprintf(file, "%lu\n", timearray[j]);
        }
        fclose(file);
        printf("AES timing samples saved to aes.txt\n");
    } else {
        fprintf(stderr, "Error opening aes.txt for writing\n");
    }

    printf("AES Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);
}

void rsa_perf() {
    int i;
    uint64_t t1, t2;
    uint64_t timearray[1000000];

    EVP_PKEY *evp_rsa = EVP_PKEY_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    RSA *rsa = RSA_new_method(NULL);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);

    EVP_PKEY_assign(evp_rsa, EVP_PKEY_RSA, rsa);

    unsigned char plaintext[16] = "TestMessage1234"; // 16-byte plaintext
    unsigned char ciphertext[256];  // Buffer for ciphertext
    size_t ciphertext_len;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_rsa, NULL);
    EVP_PKEY_encrypt_init(ctx);

    for(i = 0; i < 1000000; i++) {
        t1 = timer_start();
        size_t len = sizeof(ciphertext);
        if (EVP_PKEY_encrypt(ctx, ciphertext, &len, plaintext, sizeof(plaintext)) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        ciphertext_len = len; // Store the length of the ciphertext
        t2 = timer_stop();
        timearray[i] = t2 - t1;
    }

    FILE *file = fopen("rsa.txt", "w");
    if (file) {
        for (int j = 0; j < 1000000; j++) {
            fprintf(file, "%lu\n", timearray[j]);
        }
        fclose(file);
        printf("RSA timing samples saved to rsa.txt\n");
    } else {
        fprintf(stderr, "Error opening rsa.txt for writing\n");
    }

    printf("RSA Ciphertext: ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_rsa);
    BN_free(bn);
}

void kyber_perf() {
    int i;
    uint64_t t1, t2;
    uint64_t timearray[1000000];

    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    uint8_t ciphertext[KYBER_CIPHERTEXTBYTES];
    uint8_t shared_secret[KYBER_SSBYTES];
    uint8_t message[KYBER_MESSAGELEN]; // Message to encrypt

    // Generate a random message
    if (RAND_bytes(message, sizeof(message)) != 1) {
        fprintf(stderr, "Random message generation failed\n");
        return;
    }

    // Key generation
    if (kyber_keypair(pk, sk) != 0) {
        fprintf(stderr, "Keypair generation failed\n");
        return;
    }

    for(i = 0; i < 1000000; i++) {
        t1 = timer_start();
        if (kyber_enc(ciphertext, shared_secret, message, pk) != 0) {
            fprintf(stderr, "Encryption failed\n");
        }
        t2 = timer_stop();
        timearray[i] = t2 - t1;
    }

    FILE *file = fopen("kyber.txt", "w");
    if (file) {
        for (int j = 0; j < 1000000; j++) {
            fprintf(file, "%lu\n", timearray[j]);
        }
        fclose(file);
        printf("Kyber timing samples saved to kyber.txt\n");
    } else {
        fprintf(stderr, "Error opening kyber.txt for writing\n");
    }

    printf("Kyber Ciphertext: ");
    for (size_t i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
}

int main() {
    aes_perf();  // Run AES performance test
    rsa_perf();  // Run RSA performance test
    kyber_perf(); // Run Kyber performance test
    return 0;
}
