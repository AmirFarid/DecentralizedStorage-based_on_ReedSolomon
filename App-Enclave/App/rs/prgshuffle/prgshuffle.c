
#include <stdint.h>
#include <math.h>
#include <string.h>

// #include "aes/aes.h"


uint32_t feistel_round(uint32_t half, uint8_t *key, int round) {
    // Example: simple key+round XOR then hash
    uint32_t data = half ^ ((key[round % 16] << 24) | (key[(round + 1) % 16] << 16));
    data = ((data >> 16) ^ data) * 0x45d9f3b;
    data = ((data >> 16) ^ data) * 0x45d9f3b;
    data = (data >> 16) ^ data;
    return data;
}


uint32_t feistel_prp(uint32_t input, uint32_t N, uint8_t *key, int num_rounds) {
    int num_bits = (int)ceil(log2(N));
    uint32_t mask = (1U << (num_bits / 2)) - 1;

    uint32_t L = input >> (num_bits / 2);
    uint32_t R = input & mask;

    for (int i = 0; i < num_rounds; i++) {
        uint32_t F = feistel_round(R, key, i);
        F = F & mask;
        uint32_t temp = L;
        L = R;
        R = temp ^ F;
    }

    return ((L << (num_bits / 2)) | R) % N;
}

uint32_t feistel_prp_inverse(uint32_t output, uint32_t N, uint8_t *key, int num_rounds) {
    int num_bits = (int)ceil(log2(N));
    uint32_t mask = (1U << (num_bits / 2)) - 1;

    uint32_t L = output >> (num_bits / 2);
    uint32_t R = output & mask;

    for (int i = num_rounds - 1; i >= 0; i--) {
        uint32_t F = feistel_round(L, key, i);
        F = F & mask;
        uint32_t temp = R;
        R = L;
        L = temp ^ F;
    }

    return ((L << (num_bits / 2)) | R) % N;
}
