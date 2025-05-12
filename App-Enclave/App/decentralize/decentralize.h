#ifndef DECENTRALIZE_H
#define DECENTRALIZE_H

#include <sgx_urts.h>


void preprocessing(sgx_enclave_id_t eid, int mode, char* fileChunkName, int *numBlocks);




#endif