#ifndef DECENTRALIZE_H
#define DECENTRALIZE_H

#include <sgx_urts.h>
#include <sgx_tseal.h>
#include "sharedTypes.h"

void preprocessing(sgx_enclave_id_t eid, int mode, char* fileChunkName, FileDataTransfer *fileDataTransfer);




#endif