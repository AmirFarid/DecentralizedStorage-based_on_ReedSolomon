#ifndef DECENTRALIZE_H
#define DECENTRALIZE_H

#include <sgx_urts.h>
#include <sgx_tseal.h>
#include "sharedTypes.h"

void preprocessing(sgx_enclave_id_t eid, int mode, char* fileChunkName, FileDataTransfer *fileDataTransfer, int n, int k);

void load_file_data(char *file_name, int num_blocks, int mode, int k, int n, sgx_enclave_id_t eid);

int get_dcounter(void);




#endif