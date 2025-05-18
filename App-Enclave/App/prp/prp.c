/*
 *
 *
 *
 *
 */

#include <stdint.h>
#include <string.h>
#include <math.h>

#include "aes/aes.h"

void generate_round_key(const uint8_t *key, int round_num, uint8_t *round_key)
{
    // Generate a unique round key based on the key and the round number
    memcpy(round_key, key, 16);
    round_key[15] ^= round_num;
}

uint64_t round_function(uint64_t data, const uint8_t *key)
{
    AesCtx ctx;
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];

    memcpy(plaintext + 8, &data, 8);

    if (AesCtxIni(&ctx, NULL, key, KEY128, EBC) < 0)
    {
        //printf("init error\n");
        //exit(1);
    }

    if (AesEncrypt(&ctx, plaintext, ciphertext, sizeof(plaintext)) < 0)
    {
        //printf("error in encryption\n");
        //exit(1);
    }

    uint64_t result = *((uint64_t *)(ciphertext + 8)) & 0xFFFFFFFFFFFFFFFF;
    return result;
}

uint64_t feistel_network_prp(const uint8_t *key, uint64_t input_block, int num_bits)
{
    // Perform a fixed number of rounds (e.g., 4 rounds)
	if(num_bits == 0) {
		return 0;
	}
    int num_rounds = 4;
    int round_num;
    for (round_num = 0; round_num < num_rounds; round_num++)
    {
        // Compute the round key based on the current round number
        uint8_t round_key[16];
        generate_round_key(key, round_num, round_key);

        // Extract the right half of the input
        uint64_t right_half = input_block & ((1ULL << (num_bits / 2)) - 1);

        // Apply the Feistel round function
        uint64_t f_result = round_function(right_half, round_key);

        // XOR the result of the round function with the left half
        input_block ^= (f_result << (num_bits / 2));
    }

    // Return the result
    return input_block << (64 - num_bits) >> (64 - num_bits);
}

uint64_t feistel_network_prp2(const uint8_t *key, uint64_t block, int num_bits, int inverse) {
    if (num_bits == 0 || num_bits > 64 || num_bits % 2 != 0)
        return 0;

    int half_bits = num_bits / 2;
    uint64_t mask = (half_bits == 64) ? ~0ULL : ((1ULL << half_bits) - 1);

    uint64_t left = (block >> half_bits) & mask;
    uint64_t right = block & mask;

    if (!inverse) {
        // ENCRYPTION: Standard Feistel rounds
        for (int i = 0; i < 4; i++) {
            uint8_t round_key[16];
            generate_round_key(key, i, round_key);

            uint64_t f_result = round_function(right, round_key);

            uint64_t new_left = right;
            uint64_t new_right = left ^ (f_result & mask);

            left = new_left;
            right = new_right;
        }
    } else {
        // DECRYPTION: Inverse Feistel rounds
        for (int i = 3; i >= 0; i--) {
            uint8_t round_key[16];
            generate_round_key(key, i, round_key);

            uint64_t f_result = round_function(left, round_key);

            uint64_t old_right = left;
            uint64_t old_left = right ^ (f_result & mask);

            left = old_left;
            right = old_right;
        }
    }

    return (left << half_bits) | right;
}
