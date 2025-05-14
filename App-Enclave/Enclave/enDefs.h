#ifndef ENDEFS_H
#define ENDEFS_H
#include <stdint.h>
#include <openssl/bn.h>
#include "sharedTypes.h"

#define AUDIT_INDICATOR  "AUDITX"
#define ENCODE_INDICATOR "ENCODE"
#define PARITY_INDICATOR "PARITY"

// Amir MM Farid
#define talloc(type, num) ((type *) malloc((num) * sizeof(type)))
// end Amir MM Farid


typedef struct PorSK {
	uint8_t encKey[KEY_SIZE];
	uint8_t macKey[MAC_SIZE];
} PorSK;

// // Amir MM Farid
// // peer info
// typedef struct {
//     const char* ip;
// 	uint8_t is_parity_peer;
// 	uint8_t chunk_id;
//     int port;
//     int socket_fd;
//     int is_ready;
// } NodeInfo;
// // end Amir MM Farid

// n and k are the erasure code parameters for an (n, k) erasure code.
typedef struct File {
	int inUse;
	int numBlocks;
	int numGroups;
	int n;
	int k;
	// Amir MM Farid
	uint8_t is_parity_peer;
	NodeInfo *nodes;
	uint8_t dh_sharedKey[64];
	// parity shuffle key
	uint8_t parity_sharedKey_AES[64];

	// end Amir MM Farid
	char fileName[FILE_NAME_LEN];
	uint8_t prime[PRIME_LENGTH / 8];
	uint8_t sortKey[KEY_SIZE]; // I never define this. I should randomly generate it in file_init.
} File;

extern File files[MAX_FILES];

extern PorSK porSK;

extern uint8_t dh_sharedKey[64];

#endif
