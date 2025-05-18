#ifndef PRP_H

#include <stdint.h>

uint64_t feistel_network_prp(const uint8_t *key, uint64_t input_block, int num_bits);
uint64_t feistel_network_prp2(const uint8_t *key, uint64_t block, int num_bits, int inverse);

#endif
