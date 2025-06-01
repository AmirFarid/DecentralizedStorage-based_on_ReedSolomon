#ifndef RS_H
#define RS_H

#include <stdint.h>

void initiate_rs(const char *original_file, int K, int N);

void decode(int chunk_size, int *erasures, int *code_word, int *code_word_index, int *matrix, int current_chunk_id, uint16_t *recovered_data);


#endif