#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H


#define KEY_SIZE 16
#define PUB_SIZE 64
#define PRV_SIZE 32
#define MAC_SIZE 20
#define PRIME_LENGTH 80
#define SHA_DIGEST_LENGTH 20

#define BLOCK_SIZE 4096 // Note: these depend on the storage device being used.
#define PAGE_SIZE 2048
#define SEGMENT_SIZE 512
#define PAGE_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define SEGMENT_PER_BLOCK (BLOCK_SIZE / SEGMENT_SIZE)
#define SEGMENT_PER_PAGE (PAGE_SIZE / SEGMENT_SIZE)

#define FILE_NAME_LEN 512
#define MAX_FILES 10

#define NUM_CHAL_BLOCKS 1
#define NUM_ORIGINAL_SYMBOLS 2 // Erasure code parameters. Maybe should be part of File struct
#define NUM_TOTAL_SYMBOLS 3

#define SECRET_LENGTH ((PAGE_SIZE * 8) / 256) // One bit in secret message every 512 bits.
#define PARITY_START 5000 // Start address for parity data.


// #define N 5 // Number of chunks
// #define K 3 // Number of original data chunks
// #define M (N - K) // Number of parity chunks

// Amir MM Farid
// Number of nodes also needs to be changed in Enclave.edl for the function ecall_init
#define NUM_NODES 2
#define OWNER_IP "127.0.0.1"
#define OWNER_PORT 8080



typedef struct {
    char ip[30];
    int port;
	uint8_t is_parity_peer;
	uint8_t chunk_id;
    // peers communication keys
	uint8_t dh_sharedKey_peer2peer[64];
    int socket_fd;
} NodeInfo;


// the file information gathered and send to enclave ( it is similar to the concept of DTO in Java)
typedef struct {
    NodeInfo nodes[NUM_NODES];
    int n;
    int k;
    int current_id;
    char fileName[256];
    int numBlocks;
    char owner_ip[16];
    int owner_port;
} FileDataTransfer;
// end Amir MM Farid

typedef struct Tag {
    int n;
    uint8_t prfKey[KEY_SIZE];
	uint8_t alpha[SEGMENT_PER_BLOCK][PRIME_LENGTH / 8];
	uint8_t MAC[MAC_SIZE];
} Tag;

#endif
