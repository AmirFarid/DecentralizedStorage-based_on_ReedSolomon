#ifndef PRGSHUFFLE_H
#define PRGSHUFFLE_H

#include <stdint.h>




uint32_t feistel_prp(uint32_t input, uint32_t N, uint8_t *key, int num_rounds);


uint32_t feistel_prp_inverse(uint32_t output, uint32_t N, uint8_t *key, int num_rounds);







#endif