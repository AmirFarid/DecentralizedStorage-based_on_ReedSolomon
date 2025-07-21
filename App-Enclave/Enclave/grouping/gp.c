#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>

// #define MAX_GROUPS 100
// #define MAX_GROUP_SIZE 100
// #define N 300
// #define G 5
// const char* KEY = "000000000000kjkdsid0000000001111";

// int M = N / G; // Number of tuples

// SHA256-based seed generator
uint64_t get_seed(const char* key, int* data, int size) {
    unsigned char buffer[256];
    // snprintf(buffer, sizeof(buffer), "%s", key);
    // for(int i = 0; i < 16; i++){
    //     printf("Shuffle_key[%d] = %02x\n", i, key[i]);
    // }
    int offset = 0;
    for (int i = 0; i < 16; i++) {
        // printf("hi its me\n");
        snprintf(buffer + offset, sizeof(buffer),"%02x", (unsigned char)key[i]);
        // printf("key[%d] = %02x\n", i, (unsigned char)key[i]);
        offset += 2;
        // printf("buffer[%d] = %c\n", 2*i, buffer[2*i]);
        // printf("buffer[%d] = %c\n", 2*i+1, buffer[2*i+1]);


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

// Generates structured tuples, each containing one item from each original group
// void generate_structured_tuples(int tuples[MAX_GROUPS][G], int* num_tuples, const char* key) {
//     int original[G][MAX_GROUP_SIZE];
//     int M = N / G;
//     *num_tuples = M;

//     for (int g = 0; g < G; g++) {
//         for (int i = 0; i < M; i++) {
//             original[g][i] = g * M + i;
//         }
//         uint64_t seed = get_seed(key, &g, 1);
//         seeded_shuffle(original[g], M, seed);
//     }

//     for (int i = 0; i < M; i++) {
//         for (int g = 0; g < G; g++) {
//             tuples[i][g] = original[g][i];
//         }
//     }
// }

// // Return the tuple that contains the digit
// int get_tuple_for_digit(int digit, int tuples[MAX_GROUPS][G], int num_tuples, int* out_tuple) {
//     for (int i = 0; i < num_tuples; i++) {
//         for (int j = 0; j < G; j++) {
//             if (tuples[i][j] == digit) {
//                 memcpy(out_tuple, tuples[i], sizeof(int) * G);
//                 return 1;
//             }
//         }
//     }
//     return 0;
// }


int find_tuple_for_digit(const char* key, int digit, int *out_tuple, int total_num_blocks, int group_size) {
    int M = total_num_blocks / group_size;
    int group_id = digit / M;
    int index_in_group = -1;

    ocall_printf("this is the key:", strlen("this is the key:"), 0);
    ocall_printf(key, 16, 1);
    ocall_printf("this is the digit:", strlen("this is the digit:"), 0);
    ocall_printint(&digit);
    ocall_printf("this is the total_num_blocks:", strlen("this is the total_num_blocks:"), 0);
    ocall_printint(&total_num_blocks);
    ocall_printf("this is the group_size:", strlen("this is the group_size:"), 0);
    ocall_printint(&group_size);
    

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
        ocall_printf("this is the out_tuple:", strlen("this is the out_tuple:"), 0);
        ocall_printint(&out_tuple[g]);
    }

    return 1;
}


// int main() {
//     int tuples[MAX_GROUPS][G];
//     int num_tuples;

//     generate_structured_tuples(tuples, &num_tuples, KEY);

//     printf("Structured Tuples:\n");
//     for (int i = 0; i < num_tuples; i++) {
//         // printf("Tuple %d: ", i);
//         for (int j = 0; j < G; j++) {
//             printf("%d ", tuples[i][j]);
//         }
//         printf("\n");
//     }

//     int digit = 3;
//     int result[G];
//     if (get_tuple_for_digit(digit, tuples, num_tuples, result)) {
//         printf("\nDigit %d belongs to tuple: (", digit);
//         for (int i = 0; i < G; i++) {
//             printf("%d%s", result[i], i < G - 1 ? ", " : "");
//         }
//         printf(")\n");
//     } else {
//         printf("\nDigit %d does not belong to any tuple.\n", digit);
//     }



// int t[G];
// if (find_tuple_for_digit(KEY, 3, t)) {
//     printf("Digit 3 belongs to tuple: (");
//     for (int i = 0; i < G; i++) printf("%d%s", t[i], i < G - 1 ? ", " : ")\n");
// }


//     return 0;
// }
