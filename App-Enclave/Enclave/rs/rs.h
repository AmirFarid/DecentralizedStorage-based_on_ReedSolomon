#ifndef RS_H
#define RS_H

#include <stdint.h>

void initiate_rs(const char *original_file, int K, int N);

void decode(int chunk_size, int *erasures);


#endif