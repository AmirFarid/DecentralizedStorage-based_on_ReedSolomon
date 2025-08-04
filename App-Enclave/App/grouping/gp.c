#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>



// SHA256-based seed generator
uint64_t get_seed(const char* key, int* data, int size) {
    unsigned char buffer[256];
    int offset = 0;
    for (int i = 0; i < 16; i++) {
        snprintf(buffer + offset, sizeof(buffer),"%02x", (unsigned char)key[i]);
        offset += 2;
    }
    for (int i = 0; i < size; i++) {
        char num[12];
        snprintf(num, sizeof(num), ":%d", data[i]);
        strncat(buffer, num, sizeof(buffer) - strlen(buffer) - 1);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)buffer, strlen(buffer), hash);
    uint64_t seed = 0;
    for (int i = 0; i < 8; i++) seed = (seed << 8) | hash[i];
    return seed;
}

uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

void seeded_shuffle(int* arr, int size, uint64_t seed) {
    uint64_t state = seed;
    for (int i = size - 1; i > 0; i--) {
        int j = xorshift64(&state) % (i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}



int find_tuple_for_digit(const char* key, int digit, int *out_tuple, int total_num_blocks, int group_size) {
    int M = total_num_blocks / group_size;
    int group_id = digit / M;
    int index_in_group = -1;

    // Regenerate and shuffle the group where the digit belongs
    int group[M];
    for (int i = 0; i < M; i++) {
        group[i] = group_id * M + i;
    }

    uint64_t seed = get_seed(key, &group_id, 1);
    seeded_shuffle(group, M, seed);

    for (int i = 0; i < M; i++) {
        if (group[i] == digit) {
            index_in_group = i;
            break;
        }
    }

    if (index_in_group == -1) return 0;  // Should not happen unless digit is out of range

    // Build the tuple at position index_in_group
    for (int g = 0; g < group_size; g++) {
        int grp[M];
        for (int i = 0; i < M; i++) {
            grp[i] = g * M + i;
        }
        uint64_t seed = get_seed(key, &g, 1);
        seeded_shuffle(grp, M, seed);
        out_tuple[g] = grp[index_in_group];
    }

    return 1;
}
