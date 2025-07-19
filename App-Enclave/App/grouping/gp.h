#ifndef GP_H
#define GP_H

#include <stdint.h>

int find_tuple_for_digit(const char* key, int digit, int *out_tuple, int total_num_blocks, int group_size);

#endif