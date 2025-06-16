#ifndef RS_H
#define RS_H

#include <stdint.h>

void initiate_rs(int K, int N);

void decode(int chunk_size, int *erasures, int *code_word, int *matrix, int current_chunk_id);


#endif