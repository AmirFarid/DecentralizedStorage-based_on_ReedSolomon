// Amir M M Farid

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "decentralize.h"
#include "sgx_urts.h"
#include "sharedTypes.h"
#include <stdio.h>
#include "Enclave_u.h"
#include <openssl/rand.h>
#include "prng.h"
#include "ecdh.h"
#include "jerasure/reed_sol.h"
#include <math.h>
#include "../hmac/hmac.h"

#include "../rs/rs.h"
#include "../aes/aes.h"

int Number_Of_Blocks;
int Current_Chunk_ID;

uint8_t *ALL_DATA;
uint8_t *SIGNATURES;
int N;
int K;
// #define N 5
// #define K 3
// define all the types that reciver can accept
typedef enum
{
    INIT = 0,
    CHUNK = 1,
    PARITY_KEY = 2,
    BLOCK = 3,
    CODE_WORD = 4,
} RequestType;

NodeInfo nodes[NUM_NODES] = {
    {"141.219.248.128", 8080, -1, 0}, // This is the host node do not count it as a node
    {"141.219.249.254", 8080, -1, 0},
    // {"141.219.210.172", 8080, -1, 0},
    {"141.219.250.6", 8080, -1, 0},
    // {"141.219.250.6", 8080, -1, 0},


    {"141.219.210.172", 8080, -1, 0},
    // {"141.219.250.6", 8080, -1, 0},
    // for the parity node I have to retrive it from the first node while if the parity was required in the first node I have to fake it from the second node and 
    // {"192.168.1.1", 8080, -1, 0}, // This is the host node do not count it as a node
    {"141.219.248.128", 8080, -1, 0},

    // {"141.219.210.172", 8080, -1, 0},

    // {"192.168.1.2", 8081, -1, 0},
    // {"192.168.1.3", 8082, -1, 0}
};

typedef struct
{
    uint8_t *output_code_word_buffer;
    pthread_mutex_t lock;
    int *output_index_list;
    uint8_t *output_signature_list;
} ThreadSharedArgs;

typedef struct
{
    int node_id;
    int node_port;
    char node_ip[16];
    int fileNum;
    int blockNum;
    void *shared_args;
    int offset;
    int fake;
    int total_blocks_index;
} ThreadWrapperArgs;

typedef struct
{
    uint8_t *current_pubKey;
    uint8_t *peer_pubKey;
    char *ip;
    int port;
    int *socket_fd;
    int current_id;
} ThreadArgs;


typedef struct{
    int client_socket;
    sgx_enclave_id_t eid;
    pthread_mutex_t lock;
}server_args;

#define CHUNK_PATH_FORMAT "App/decentralize/chunks/data_%d.dat"
#define CHUNK_PATH_FORMAT2 "App/decentralize/NF/data_%d.dat"
#define CHUNK_BUFFER_SIZE 1024

// Parity chunk encryption key
uint8_t PC_KEY[KEY_SIZE];
uint8_t sig_key[32];
uint8_t Shuffle_key[KEY_SIZE];

typedef struct
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
    return (x << k) | (x >> (32 - k));
}

static uint32_t prng_next(void)
{
    uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
    prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
    prng_ctx.b = prng_ctx.c + prng_ctx.d;
    prng_ctx.c = prng_ctx.d + e;
    prng_ctx.d = e + prng_ctx.a;
    return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
    uint32_t i;
    prng_ctx.a = 0xf1ea5eed;
    prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

    for (i = 0; i < 31; ++i)
    {
        (void)prng_next();
    }
}

// ------------------------------------------------------------------------------
//                            helper functions  
                               
void init_keys()
{

    uint32_t seed;
    RAND_bytes((unsigned char *)&seed, sizeof(seed)); // 32 bits of entropy
    prng_init(seed);
    for (int i = 0; i < 16; i++)
    {
        PC_KEY[i] = prng_next();
    }

    // generate the shuffle key
    uint32_t seed2;
    RAND_bytes((unsigned char *)&seed2, sizeof(seed2));
    prng_init(seed2);
    for (int i = 0; i < KEY_SIZE; i++)
    {
        Shuffle_key[i] = prng_next();
    }

    // generate the signature key
    uint32_t seed3;
    RAND_bytes((unsigned char *)&seed3, sizeof(seed3));
    prng_init(seed3);
    for (int i = 0; i < 32; i++)
    {
        sig_key[i] = prng_next();
    }
}

int permutation(int i, int num_bits, int bound){

    uint64_t permuted_index = feistel_network_prp(Shuffle_key, i, num_bits);
    while(permuted_index >= bound){
        permuted_index = feistel_network_prp(Shuffle_key, permuted_index, num_bits);
    }

    return permuted_index;
}

/**
 * @brief this function receives data securely from the server
 * @param sock the socket file descriptor
 * @param buf the data to receive
 * @param len the length of the data to receive
 * @return the number of bytes received
 */
ssize_t secure_recv(int sock, void *buf, size_t len)
{
    size_t total_received = 0;
    char *data = (char *)buf;

    while (total_received < len)
    {
        ssize_t received = recv(sock, data + total_received, len - total_received, 0);
        if (received < 0)
        {
            perror("Receive failed");
            return -1; // Error occurred
        }
        if (received == 0)
        {
            // Connection closed by peer
            break;
        }
        total_received += received;
    }
    return total_received; // Total bytes received
}
/**
 * @brief this function encrypts the data using AES
 * @param KEY the key to encrypt the data
 * @param buffer the data to encrypt
 * @param dataLen the length of the data to encrypt
 * @return the number of bytes encrypted
 */
#define NUM1 (1 << 24)
#define NUM2 (1 << 16)
#define NUM3 (1 << 8)
int DecryptData2(uint32_t* KEY,void* buffer, int dataLen)
{
   //decrypt after read
    AesCtx ctx;
    unsigned char iv[] = "123456789abcdef"; // Needs to be same between FTL and SGX
    unsigned char key[16];
    uint8_t i;
    for(i=0;i<4;i++){    
    	key[4*i]=(*(KEY+i))/NUM1;
    	key[(4*i)+1]=((*(KEY+i))/NUM2)%NUM3;
    	key[(4*i)+2]=(*(KEY+i)% NUM2)/NUM3;
    	key[(4*i)+3]=(*(KEY+i)% NUM2)%NUM3;
    }
    
   if( AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0) return -1;

   if (AesDecrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen) < 0) return -1;

   return 0;
}


int EncryptData2(uint32_t *KEY, void *buffer, int dataLen)
{
    // encrypt before writing
    AesCtx ctx;
    unsigned char iv[] = "123456789abcdef";
    // unsigned char key[] = "876543218765432";
    unsigned char key[16];
    uint8_t i;
    for (i = 0; i < 4; i++)
    {
        key[4 * i] = (*(KEY + i)) / NUM1;
        key[(4 * i) + 1] = ((*(KEY + i)) / NUM2) % NUM3;
        key[(4 * i) + 2] = (*(KEY + i) % NUM2) / NUM3;
        key[(4 * i) + 3] = (*(KEY + i) % NUM2) % NUM3;
    }
    for (i = 0; i < 16; i++)
    {
        // uart_printf("EncryptData():the %d byte of key is %x\n\r",i,key[i]);
    }

    // uart_printf("before encrypt: %s\n\r", buffer);

    // initialize context and encrypt data at one end
    if (AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0)
    {
        // uart_printf("init error\n");
    }

    int flag = 0;
    if ((flag = AesEncrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen)) < 0)
    // dataLen needs to be different based on PDP vs ECC. Full 512 byte segment for ECC. KEY_SIZE for PDP.
    {
        // uart_printf("error in encryption\n");
        if (flag == -2)
        {
            // uart_printf("Data is empty");
            // return -2;
        }
        else if (flag == -3)
        {
            // uart_printf("cipher is empty");
            // return -3;
        }
        else if (flag == -4)
        {
            // uart_printf("context is empty");
            // return -4;
        }
        else if (flag == -5)
        {
            // uart_printf("data length is not a multiple of 16");
            // return -5;
        }
        else
        {
            // uart_printf("other error");
        }
    }
    else
    {
        // uart_printf("encryption ok %d\n\r",count_write);
        // uart_printf("after encrypt: %s\n\r", buffer);
    }
    return 0;
}

/**
 * @brief this function sends data securely to the server
 * @param sock the socket file descriptor
 * @param buf the data to send
 * @param len the length of the data to send
 * @return the number of bytes sent
 */
ssize_t secure_send(int sock, const void *buf, size_t len)
{
    size_t total_sent = 0;
    const char *data = (const char *)buf;

    while (total_sent < len)
    {
        ssize_t sent = send(sock, data + total_sent, len - total_sent, 0);
        if (sent < 0)
        {
            perror("Send failed");
            return -1; // Error occurred
        }
        total_sent += sent;
    }
    return total_sent; // All data sent successfully
}

// void ack_recv(int client_socket)
// {
//     char ack_buf[4];
//     if (recv(client_socket, ack_buf, sizeof(ack_buf), 0) > 0) {
//         printf("Received ACK: %s\n", ack_buf);
//     }
// }
void ack_recv(int client_socket)
{
    char ack_buf[5] = {0};  // 4 bytes for data, 1 for '\0'
    ssize_t len = recv(client_socket, ack_buf, 4, 0);
    if (len > 0) {
        ack_buf[len] = '\0';  // Ensure null-termination
        printf("Received ACK: %s\n", ack_buf);
    }
}
void ack_send(int client_socket)
{
    secure_send(client_socket, "ACK", 3);

}




void ocall_write_recovered_file(uint8_t *data, size_t file_size) {
    FILE *fp = fopen("recovered.bin", "wb");
    if (fp == NULL) {
        perror("Failed to open recovered.bin");
        return;
    }

    size_t written = fwrite(data, 1, file_size, fp);
    if (written != file_size) {
        fprintf(stderr, "Warning: only wrote %zu of %zu bytes\n", written, file_size);
    } else {
        printf("Successfully wrote %zu bytes to recovered.bin\n", file_size);
    }

    fclose(fp);
}

/**
 * @brief this functin recieve first the file type and then the file size and then the file data
 * @param client_socket the client socket
 * @param save_path the path to save the file
 * @return the file path
 */
char *store_received_file(int client_socket, char *save_path)
{

    u_int32_t file_size;
    u_int32_t file_type;
    int chunk_id;

    FILE *fp = fopen(save_path, "wb");
    if (!fp)
    {
        perror("Failed to open file for writing");
        return NULL;
    }

    ssize_t len;

    int n;
    int k;

    

    secure_recv(client_socket, Shuffle_key, sizeof(Shuffle_key));

    secure_recv(client_socket, &n, sizeof(int));
    secure_recv(client_socket, &k, sizeof(int));

    N = n;
    K = k;
    // receive the file type and size
    secure_recv(client_socket, &chunk_id, sizeof(int));
    secure_recv(client_socket, &file_type, sizeof(u_int32_t));
    secure_recv(client_socket, &file_size, sizeof(u_int32_t));

    Current_Chunk_ID = chunk_id;

 
    // while ((len = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
    // while ((len = secure_recv(client_socket, buffer, file_size)) > 0) {

    Number_Of_Blocks = file_size / BLOCK_SIZE;
    if(file_type == 1){
        uint8_t buffer[CHUNK_BUFFER_SIZE];
        for (size_t i = 0; i < file_size / CHUNK_BUFFER_SIZE; i++)
    {
        len = secure_recv(client_socket, buffer, CHUNK_BUFFER_SIZE);
            printf("this is the %d th len: %d\n", i, len);
            fwrite(buffer, 1, len, fp);
        }
    }
    else{
        uint8_t buffer[BLOCK_SIZE];
        for (size_t i = 0; i < Number_Of_Blocks; i++)
        {
            len = secure_recv(client_socket, buffer, BLOCK_SIZE);
            if(chunk_id < K){
                printf("this is the %d th block stored\n", chunk_id);
                fwrite(buffer, 1, len, fp);
            }else{
                printf("Just Fake for %d peer\n", chunk_id);
            }
        }
    }


    fclose(fp);

    if (len < 0)
    {
        perror("recv failed");
        return NULL;
    }

    // Return the file path (you could also return strdup(save_path))
    return strdup(save_path);
}

/**
 * @brief this function gets the size of the file
 * @param file the file pointer
 * @return the size of the file
 */
static long get_file_size(FILE *file)
{
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    return size;
}

/**
 * @brief this function sets up the server socket on port 8080
 * @return the server socket file descriptor
 */
int setup_server_socket()
{

    int port = 8080;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket failed");
        return -1;
    }

    // Allow port reuse
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        close(server_fd);
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY};

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind failed");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("listen failed");
        close(server_fd);
        return -1;
    }

    printf("Server is listening on port %d\n", port);
    return server_fd;
}

/**
 * @brief this function renames the file
 * @param old_name the old name of the file
 * @param new_name the new name of the file
 * @return 0 if the file is renamed successfully, -1 otherwise
 */
int rename_file(const char *old_name, const char *new_name)
{
    if (rename(old_name, new_name) == 0)
    {
        printf("File renamed successfully from '%s' to '%s'.\n", old_name, new_name);
        return 0; // success
    }
    else
    {
        perror("Error renaming file");
        return -1;
    }
}
// ------------------------------------------------------------------------------
//                                 Receiver functions

void ocall_get_shuffle_key(u_int8_t *Sh_key, u_int8_t *sig_key, u_int8_t *Kexchange_PUB_KEY, u_int8_t *Kexchange_DataOwner_PUB_KEY, u_int8_t *PARITY_AES_KEY, char *owner_ip, int owner_port)
{
    // printf("Shuffle key: %s\n", Shuffle_key);
    printf("Owner IP: %s\n", owner_ip);
    printf("Owner Port: %d\n", owner_port);

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0)
    {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(owner_port)};

    inet_pton(AF_INET, owner_ip, &server_addr.sin_addr);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection to server failed");
        close(client_socket);
        return;
    }

    RequestType type = PARITY_KEY;


    secure_send(client_socket, &type, sizeof(type));

    // ------------------------------------------------------------
    // |             need to be done for attestation               |
    // |                         Decap                             |
    // ------------------------------------------------------------
    // ecall_get_report(eid, pub_key, quote, quote_size);
    // uint8_t quote[1024];
    // uint32_t quote_size;

    // secure_send(client_socket, &type, sizeof(type));ma


    secure_send(client_socket, Kexchange_PUB_KEY, PUB_SIZE);
    printf("Kexchange_PUB_KEY: %s\n", Kexchange_PUB_KEY);

    secure_recv(client_socket, Kexchange_DataOwner_PUB_KEY, PUB_SIZE);
    printf("Kexchange_DataOwner_PUB_KEY: %s\n", Kexchange_DataOwner_PUB_KEY);
    secure_recv(client_socket, Sh_key, KEY_SIZE);
    printf("Sh_key: %s\n", Sh_key);
    secure_recv(client_socket, PARITY_AES_KEY, 16);
    printf("PARITY_AES_KEY: %s\n", PARITY_AES_KEY);
    secure_recv(client_socket, sig_key, 32);
    printf("sig_key: %s\n", sig_key);

    ack_send(client_socket);
    printf("ACK sent\n");
    close(client_socket);
}

void reciever_data_initialization(char *fileChunkName)
{
    int server_socket = setup_server_socket();
    printf("Waiting for the client file...\n");

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
    if (client_socket < 0)
    {
        perror("Accept failed");
        return;
    }

    // const char *filename = "received_file.bin";
    // char received_path[PATH_MAX];
    // snprintf(received_path, sizeof(received_path), "/tmp/%s", filename);

    char *stored_path = store_received_file(client_socket, fileChunkName);
    if (stored_path)
    {
        printf("File received and saved at: %s\n", stored_path);

        // You can now use `stored_path` wherever needed

        free(stored_path);
    }

    close(client_socket);
    close(server_socket);
}
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

void initialize_peer2peer_connection(sgx_enclave_id_t eid, int client_socket)
{

    int sender_id;
    uint8_t sender_pubKey[PUB_SIZE];
    uint8_t current_pubKey[PUB_SIZE];

    secure_recv(client_socket, &sender_id, sizeof(sender_id));

    secure_recv(client_socket, sender_pubKey, PUB_SIZE);

    // get the sender ip and port
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if (getpeername(client_socket, (struct sockaddr *)&addr, &addr_len) == -1)
    {
        perror("getpeername failed");
        return;
    }

    char ip_str[INET_ADDRSTRLEN]; // enough for IPv4
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));

    for (int i = 0; i < 16; i++) {
        printf("sends to ip: %c\n", ip_str[i]);
    }


    int port = ntohs(addr.sin_port);

    printf("Client IP: %s\n", ip_str);
    printf("Client Port: %d\n", port);

    // printf("pubkey: %d\n", current_pubKey);

    int current_id;

    ecall_get_currentID(eid, &current_id);


    ecall_peer_init(eid, current_pubKey, sender_pubKey, ip_str, sender_id);

    secure_send(client_socket, current_pubKey, PUB_SIZE);

    printf("########################Id Sends to#################################\n");
    printf("sends to ip: %s\n", ip_str);
    printf("sends to port: %d\n", port);
    printf("current_id: %d\n", current_id);
    printf("########################&&&&& Sends to##############################\n");
    
    int current_id_tmp = current_id;
    if (secure_send(client_socket, &current_id_tmp, sizeof(int)) != sizeof(int))
    {
        printf("Failed to send current id to ip %s\n", ip_str);
        close(client_socket);
        return;
    }

    ack_recv(client_socket);

}

// #include <sgx_dcap_quoteverify.h>
// #include <openssl/sha.h>

// the owner of data he needs to make sure the key requested from TEE is correct
void handle_key_exchange(sgx_enclave_id_t eid, int client_socket)
{

    // Parity Key Exchange

    uint8_t Requester_PUB_KEY[PUB_SIZE];

    uint8_t Kexchange_DataOwner_PUB_KEY[64];
    uint8_t Kexchange_DataOwner_prv_KEY[32];

    uint8_t sharedKey[64];

    uint32_t seed;
    RAND_bytes((unsigned char *)&seed, sizeof(seed)); // 32 bits of entropy
    prng_init(seed);
    for (int i = 0; i < 32; i++)
    {
        Kexchange_DataOwner_prv_KEY[i] = prng_next();
    }

    ecdh_generate_keys(Kexchange_DataOwner_PUB_KEY, Kexchange_DataOwner_prv_KEY);


    // ------------------------------------------------------------
    // |             need to be done for attestation               |
    // ------------------------------------------------------------

    //     sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    //     quote3_error_t qv_ret;

    //     uint8_t *quote = ...;       // received from enclave
    //     uint32_t quote_size = ...;  // known or transmitted
    //     time_t current_time = time(NULL);

    // // 1. Verify the quote (offline, fully local)
    //     qv_ret = sgx_qv_verify_quote(
    //         quote,
    //         quote_size,
    //         NULL,              // collateral - NULL to use default
    //         current_time,
    //         &qv_result,
    //         NULL, NULL, NULL   // optional supplemental data
    //     );

    //     if (qv_ret != SGX_QL_SUCCESS || qv_result != SGX_QL_QV_RESULT_OK) {
    //         printf("Quote verification failed\n");
    //         exit(1);
    //     }

    // enclave_attestation_send(eid, client_socket);

    // RequestType type;
    // secure_recv(client_socket, &type, sizeof(RequestType));



    secure_recv(client_socket, Requester_PUB_KEY, PUB_SIZE);

    ecdh_shared_secret(Kexchange_DataOwner_prv_KEY, Requester_PUB_KEY, sharedKey);
    
    secure_send(client_socket, Kexchange_DataOwner_PUB_KEY, PUB_SIZE);


    uint8_t Shuffle_key_tmp[KEY_SIZE];
    uint8_t PC_KEY_tmp[16];
    uint8_t sig_key_tmp[32];

    memcpy(Shuffle_key_tmp, Shuffle_key, KEY_SIZE);
    memcpy(PC_KEY_tmp, PC_KEY, 16);
    memcpy(sig_key_tmp, sig_key, 32);


    printf("Shuffle_key_tmp: ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%X", Shuffle_key_tmp[i]);
    }
    printf("\n");   

    printf("PC_KEY_tmp: ");
    for (int i = 0; i < 16; i++) {
        printf("%X", PC_KEY_tmp[i]);
    }
    printf("\n");

    printf("sig_key_tmp: ");
    for (int i = 0; i < 32; i++) {
        printf("%X", sig_key_tmp[i]);
    }
    printf("\n");
    
    

    EncryptData2(sharedKey, Shuffle_key_tmp, KEY_SIZE);
    EncryptData2(sharedKey, PC_KEY_tmp, 16);    
    EncryptData2(sharedKey, sig_key_tmp, 32);

    secure_send(client_socket, Shuffle_key_tmp, KEY_SIZE);
    secure_send(client_socket, PC_KEY_tmp, 16);
    secure_send(client_socket, sig_key_tmp, 32);

    ack_recv(client_socket);
    
}

void handle_block_retrival_request(sgx_enclave_id_t eid, int client_socket)
{

    int block_id;
    int file_id;
    uint8_t *status = malloc(sizeof(uint8_t));
    uint8_t *recovered_block = malloc(BLOCK_SIZE);
    uint8_t *signature = malloc(32);

    secure_recv(client_socket, &file_id, sizeof(int));
    secure_recv(client_socket, &block_id, sizeof(int));

    ecall_check_block(eid, file_id, block_id, status, signature, recovered_block, BLOCK_SIZE, 1);

    // comment this out for testing
    // printf("the recovered block is: ");
    // for (int i = 0; i < BLOCK_SIZE; i++)
    // {
    //     printf("%X", recovered_block[i]);
    // }
    // printf("\n");

    secure_send(client_socket, status, sizeof(uint8_t));

    if (*status == 0)
    {
        // send the chunk id so the clinet can retrive the data by reed solomon
        // secure_send(client_socket, &Current_Chunk_ID, sizeof(int));
        // send the recovered block
        secure_send(client_socket, recovered_block, BLOCK_SIZE);
        secure_send(client_socket, signature, 32);
    }
    else
    {
        secure_send(client_socket, NULL, 0);
    }

    printf("successfully sent the status and the chunk id\n");

    ack_recv(client_socket);
}

void handle_code_word_retrival_request(sgx_enclave_id_t eid, int client_socket)
{
    // CODE_WORD request handling

    int file_id;
    int code_word_id;

    secure_recv(client_socket, &file_id, sizeof(int));
    secure_recv(client_socket, &code_word_id, sizeof(int));

    uint8_t *buffer = malloc(BLOCK_SIZE * K);
    ecall_local_code_words(eid, file_id, code_word_id, buffer, BLOCK_SIZE * K);
    
    secure_send(client_socket, buffer, BLOCK_SIZE * K);

    ack_recv(client_socket);
    free(buffer);
    // int index;
    // for (int i = 0; i < K; i++) {
    //     uint8_t *buffer = malloc(BLOCK_SIZE);
    //     secure_send(client_socket, &index, sizeof(int));
    //     secure_send(client_socket, buffer, BLOCK_SIZE);
    //     free(buffer);
    // }

}
pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
void *handle_client(void *args_ptr)
{
    server_args *args = (server_args *)args_ptr;
    sgx_enclave_id_t eid = args->eid;
    int client_socket = args->client_socket;

    // Reciever side
    printf("Client connected\n");
    pthread_mutex_lock(&global_lock);
    while (1)
    {

        // uint8_t type;

        RequestType request;
        ssize_t len = recv(client_socket, &request, sizeof(RequestType), 0);

        // RequestType request = (RequestType)type;

        if (len <= 0)
            break; // client disconnected

        if (request == INIT)
        {
            printf("-------------------------------------------------------\n");
            printf("\t Initialization request received\n");
            printf("-------------------------------------------------------\n");
            initialize_peer2peer_connection(eid, client_socket);
            break;
        }
        else if (request == CHUNK)
        {
            printf("-------------------------------------------------------\n");
            printf("\t Chunk request received\n");
            printf("-------------------------------------------------------\n");
            break;
        }
        else if (request == PARITY_KEY)
        {
            printf("-------------------------------------------------------\n");
            printf("\t Parity request received\n");
            printf("-------------------------------------------------------\n");
            // for the key exchange we need attestation
            handle_key_exchange(eid, client_socket);
            break;
        }
        else if (request == BLOCK)
        {
            printf("-------------------------------------------------------\n");
            printf("\t Block request received\n");
            printf("-------------------------------------------------------\n");
            handle_block_retrival_request(eid, client_socket);
            break;
        }
        else if (request == CODE_WORD)
        {
            printf("-------------------------------------------------------\n");
            printf("\t Code word request received\n");
            printf("-------------------------------------------------------\n");
            handle_code_word_retrival_request(eid, client_socket);
            break;
        }
        else
        {
            printf("-------------------------------------------------------\n");
            printf("\t Unknown request received\n");
            printf("-------------------------------------------------------\n");
            break;
        }
    }
    pthread_mutex_unlock(&global_lock);
    free(args);
    // n--;
    // if(n <= 0) 
    // close(client_socket);
}

void *listener_thread_func(void *eid_ptr)
{

    sgx_enclave_id_t eid = *(sgx_enclave_id_t *)eid_ptr;
    int server_socket = setup_server_socket();
    if (server_socket < 0)
    {
        printf("Failed to setup server socket\n");
        return NULL;
    }

    while (1)
    {

        printf("Waiting for client connection...\n");
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);

        if (client_socket < 0)
        {
            perror("Accept failed");
            continue;
        }
        


        server_args *args = malloc(sizeof(server_args));
        args->client_socket = client_socket;
        args->eid = eid;
        pthread_mutex_init(&args->lock, NULL);


        pthread_t handler_thread;
        // n++;
        if (pthread_create(&handler_thread, NULL, handle_client, args) != 0) {
            perror("Failed to create client thread");
            close(client_socket);
            // n--;
            continue;
        }

        // handle_client(eid, client_socket); // or create another thread for each client
    }

    return NULL;
}
// ------------------------------------------------------------------------------
//                                 Sender functions
void *get_code_word(void *arg)
{
    ThreadWrapperArgs *args = (ThreadWrapperArgs *)arg;

    ThreadSharedArgs *shared_args = (ThreadSharedArgs *)args->shared_args;

    printf("Requesting data from node %d\n", args->node_id);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return NULL;
    }

    // 3. Connect to the ith node
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(args->node_port)};

    printf("server_addr.sin_addr: %s\n", args->node_ip);
    printf("server_addr.sin_port: %d\n", args->node_port);

    inet_pton(AF_INET, args->node_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection to server failed");
        close(sock);
        return NULL;
    }

    // send the request type
    RequestType request_type = CODE_WORD;

    secure_send(sock, &request_type, sizeof(RequestType));

    secure_send(sock, &args->fileNum, sizeof(int));
    // this is the code_word_number that we want to retrieve not the block number
    secure_send(sock, &args->blockNum, sizeof(int));

        uint8_t *buffer = malloc(BLOCK_SIZE * K);
        secure_recv(sock, buffer, BLOCK_SIZE * K);

        pthread_mutex_lock(&shared_args->lock);
        memcpy(shared_args->output_code_word_buffer + args->blockNum * K *  BLOCK_SIZE, buffer, BLOCK_SIZE);
        // for(int j = 0; j < BLOCK_SIZE; j++) args->output_code_word_buffer[index * BLOCK_SIZE + j] = buffer[j];
        pthread_mutex_unlock(&shared_args->lock);
        free(buffer);


    ack_send(sock);

    




}

void ocall_retrieve_code_words(int fileNum, NodeInfo *nodes, int node_size, int node_counts, uint8_t *data_tmp, int data_tmp_size, int data_tmp_count, int num_retrieval_rq_per_peer, int num_code_words_counter, int num_code_words, int remainder)
{
// INJI
    int k = K;
    int n = N;
    int symSize = 16;
    int m = n - k;


    ThreadSharedArgs *args = malloc(sizeof(ThreadSharedArgs));

    // args->output_code_word_buffer = malloc(N * BLOCK_SIZE * sizeof(uint8_t));
    // args->output_index_list = malloc(N * sizeof(uint8_t));
    args->output_code_word_buffer = malloc((num_code_words * num_retrieval_rq_per_peer) * BLOCK_SIZE * sizeof(uint8_t));
    args->output_index_list = malloc(num_code_words * num_retrieval_rq_per_peer * sizeof(uint8_t));


    pthread_mutex_init(&args->lock, NULL);

    int counter = remainder;
    int i;
    // first retrieved locally
    // int requested_code_words = total_code_words - num_code_words;

    ThreadWrapperArgs *wrapper_args = malloc((num_code_words * num_retrieval_rq_per_peer) * sizeof(ThreadWrapperArgs));
    pthread_t *threads = malloc((num_code_words * num_retrieval_rq_per_peer) * sizeof(pthread_t));

    int thread_idx = 0;
    for (int i = 1 ; i < k; i++)
    {


            printf("==============================================\n");
            printf("this is NORMAL turn: %d\n", i);
            printf("==============================================\n");
            int j;
            for(j = 0; j < num_retrieval_rq_per_peer && num_code_words_counter < num_code_words; j++){
                wrapper_args[thread_idx].fileNum = fileNum;
                wrapper_args[thread_idx].blockNum = num_code_words_counter;
                wrapper_args[thread_idx].node_id = nodes[i].chunk_id;
                memcpy(wrapper_args[thread_idx].node_ip, nodes[i].ip, 16);
                wrapper_args[thread_idx].node_port = nodes[i].port;
                wrapper_args[thread_idx].shared_args = args;
                wrapper_args[thread_idx].fake = 0;
                pthread_create(&threads[thread_idx], NULL, get_code_word, &wrapper_args[thread_idx]);
                num_code_words_counter ++;
                thread_idx ++;
            }
            if(counter > 0){
                wrapper_args[thread_idx].fileNum = fileNum;
                wrapper_args[thread_idx].blockNum = num_code_words_counter;
                wrapper_args[thread_idx].node_id = nodes[i].chunk_id;
                memcpy(wrapper_args[thread_idx].node_ip, nodes[i].ip, 16);
                wrapper_args[thread_idx].node_port = nodes[i].port;
                wrapper_args[thread_idx].shared_args = args;
                wrapper_args[thread_idx].fake = 0;
                pthread_create(&threads[thread_idx], NULL, get_code_word, &wrapper_args[thread_idx]);
                counter--;
                num_code_words_counter ++;
                thread_idx ++;
            }
    }

    for (int i = 0; i < count; i++)
    {
        /* code */
    }
    

    // before

       int counter = 0;
    for (i = 0; i < K; i++)
    {
        printf("this is the i : %d\n", i);
        if(rb_indicies[i].is_local == 1){
            printf("this is the node index inside: %d\n", rb_indicies[i].node_index);
            continue;
        }
        printf("this is the node index outside: %d\n", rb_indicies[i].node_index);
        if(rb_indicies[i].node_index < NUM_NODES){


            for(int j = 0; j < NUM_NODES; j++){

                if(rb_indicies[i].node_index == nodes[j].chunk_id){
                    wrapper_args[counter].fileNum = fileNum;
                    wrapper_args[counter].blockNum = rb_indicies[i].internal_block_index;
                    wrapper_args[counter].total_blocks_index = rb_indicies[i].total_blocks_index;
                    wrapper_args[counter].node_id = nodes[j].chunk_id;
                    for(int k = 0; k < 16; k++) wrapper_args[counter].node_ip[k] = nodes[j].ip[k];
                    wrapper_args[counter].node_port = nodes[j].port;
                    wrapper_args[counter].shared_args = args;
                    wrapper_args[counter].fake = 0;
                    wrapper_args[counter].offset = i * BLOCK_SIZE;
                    pthread_create(&threads[counter], NULL, request_data_from_node, &wrapper_args[counter]);
                    counter++;

                }

            }
        }else{

            printf("==============================================\n");
            printf("this is FAKE turn: %d\n", i);
            printf("==============================================\n");

            // this is the fake node
            wrapper_args[counter].fileNum = fileNum;
            wrapper_args[counter].blockNum = 0;
            wrapper_args[counter].total_blocks_index = rb_indicies[i].total_blocks_index;
            wrapper_args[counter].node_id = nodes[1].chunk_id;
            wrapper_args[counter].offset = i;
            wrapper_args[counter].fake = 1;
            for(int k = 0; k < 16; k++) wrapper_args[counter].node_ip[k] = nodes[1].ip[k];
            wrapper_args[counter].node_port = nodes[1].port;
            wrapper_args[counter].shared_args = args;
            pthread_create(&threads[counter], NULL, request_data_from_node, &wrapper_args[counter]);
            counter++;

            // pthread_mutex_lock(&args->lock);    
            //     memcpy(args->output_code_word_buffer + i * BLOCK_SIZE, ALL_DATA + rb_indicies[i].total_blocks_index * BLOCK_SIZE, BLOCK_SIZE);
            // pthread_mutex_unlock(&args->lock);

        }
    }

    for(int i = K; i < N; i++){
            printf("==============================================\n");
            printf("this is Parity turn: %d\n", i);
            printf("==============================================\n");

            // this is the fake node
            wrapper_args[counter].fileNum = fileNum;
            wrapper_args[counter].blockNum = 0;
            wrapper_args[counter].total_blocks_index = rb_indicies[i].total_blocks_index;
            wrapper_args[counter].node_id = nodes[1].chunk_id;
            wrapper_args[counter].offset = i;
            wrapper_args[counter].fake = 2;
            for(int k = 0; k < 16; k++) wrapper_args[counter].node_ip[k] = nodes[1].ip[k];
            wrapper_args[counter].node_port = nodes[1].port;
            wrapper_args[counter].shared_args = args;
            pthread_create(&threads[counter], NULL, request_data_from_node, &wrapper_args[counter]);
            counter++;

            // pthread_mutex_lock(&args->lock);
            //     for(int j = 0; j < BLOCK_SIZE; j++){
            //         args->output_code_word_buffer[i * BLOCK_SIZE + j] = *((uint8_t *)(ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE) + j));
            //         // args->output_code_word_buffer[i * BLOCK_SIZE + j] = ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE) + j;
            //     }
            //     // memcpy(args->output_code_word_buffer + i * BLOCK_SIZE, ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE), BLOCK_SIZE);
            // pthread_mutex_unlock(&args->lock);

            // pthread_mutex_lock(&args->lock);

            // pthread_mutex_unlock(&args->lock);

    }























    for (int i = 0; i < thread_idx; i++)
    {
        pthread_join(threads[i], NULL);
    }

    for(int i = 0; i < num_code_words; i++){
        memcpy(data_tmp + i * BLOCK_SIZE, args->output_code_word_buffer + i * BLOCK_SIZE, BLOCK_SIZE);
    }

    free(args->output_code_word_buffer);
    free(args->output_index_list);
    free(args);
    free(wrapper_args);
    free(threads);
}

void *request_data_from_node(void *arg)
{
    if (arg == NULL) {
        fprintf(stderr, "Error: received null arg pointer\n");
        return NULL;
    }

    ThreadWrapperArgs *args = (ThreadWrapperArgs *)arg;

    ThreadSharedArgs *shared_args = (ThreadSharedArgs *)args->shared_args;

    printf("Sending request to node %d for block %d\n", args->node_id, args->blockNum);

    if(args->fake == 0){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return NULL;
    }

    // 3. Connect to the ith node
    struct sockaddr_in server_addr = {  
        .sin_family = AF_INET,
        .sin_port = htons(args->node_port)};

    printf("server_addr.sin_addr: %s\n", args->node_ip);
    printf("server_addr.sin_port: %d\n", args->node_port);

    inet_pton(AF_INET, args->node_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection to server failed");
        close(sock);
        return NULL;
    }
    // send the request type
    RequestType request_type = BLOCK;
    secure_send(sock, &request_type, sizeof(RequestType));
    secure_send(sock, &args->fileNum, sizeof(int));
    secure_send(sock, &args->blockNum, sizeof(int));

    printf("the file num is: %d\n", args->fileNum);
    printf("the block num is: %d\n", args->blockNum);
    printf("the offset is: %d\n", args->offset);
    printf("successfully sent the file num and block num\n");

    uint8_t status;
    // receive the block
    secure_recv(sock, &status, sizeof(uint8_t));

    printf("Status received\n");
    printf("the status is: %d\n", status);

        // int index;
        // secure_recv(sock, &index, sizeof(int));

        // printf("the index is: %d\n", index);

        // printf("-------- ---------------- ------------------ ----------------\n");

    if (status == 0)
    {

        uint8_t *buffer = malloc(BLOCK_SIZE);
        uint8_t *signature = malloc(32);
        printf("Buffer allocated\n");
        secure_recv(sock, buffer, BLOCK_SIZE);
        secure_recv(sock, signature, 32);

        pthread_mutex_lock(&shared_args->lock);
        memcpy(shared_args->output_code_word_buffer + args->offset , buffer, BLOCK_SIZE);
        memcpy(shared_args->output_index_list + args->offset/BLOCK_SIZE * 32, signature, 32);
        pthread_mutex_unlock(&shared_args->lock);

        printf("successfully copied the block to the output buffer\n");
        free(buffer);
        free(signature);
    }
    else{
        printf("Node %d does not have the block %d\n", args->node_id, args->offset/BLOCK_SIZE);

        pthread_mutex_lock(&shared_args->lock);
        for(int i = 0; i < K; i++){
            if(shared_args->output_index_list[i] == -1){
                shared_args->output_index_list[i] = args->offset/BLOCK_SIZE;
                break;
            }
        }
        pthread_mutex_unlock(&shared_args->lock);
    }

    ack_send(sock);
    
    close(sock);
    }else if(args->fake == 1){
            pthread_mutex_lock(&shared_args->lock);    
                memcpy(shared_args->output_code_word_buffer + args->offset * BLOCK_SIZE, ALL_DATA + args->total_blocks_index * BLOCK_SIZE, BLOCK_SIZE);




                printf("this is the code word: fake 1 %d\n", args->offset);
                for(int i = 0; i < BLOCK_SIZE; i++){
                    printf("%X ", shared_args->output_code_word_buffer[args->offset * BLOCK_SIZE + i]);
                }
                printf("\n");
                memcpy(shared_args->output_signature_list + args->offset * 32, SIGNATURES + (args->total_blocks_index * 32), 32);
                printf("this is the signature: fake 1 %d\n", args->offset);
                for(int i = 0; i < 32; i++){
                    printf("%X ", shared_args->output_signature_list[args->offset * 32 + i]);
                }
                printf("\n");
            pthread_mutex_unlock(&shared_args->lock);
    }else{
        pthread_mutex_lock(&shared_args->lock);
            printf("this is dada fake 2 %d\n", args->offset);
            printf("this is the total blocks index: %d\n", args->total_blocks_index);

            for(int j = 0; j < BLOCK_SIZE; j++){
                if(j < 40){
                printf("%X", ALL_DATA[K * Number_Of_Blocks * BLOCK_SIZE + (args->total_blocks_index * BLOCK_SIZE) + j]);
                }
                shared_args->output_code_word_buffer[args->offset * BLOCK_SIZE + j] = ALL_DATA[K * Number_Of_Blocks * BLOCK_SIZE + (args->total_blocks_index * BLOCK_SIZE) + j];
                    // shared_args->output_index_list[args->offset * 32 + j] = SIGNATURES[K * Number_Of_Blocks * 32 + (args->total_blocks_index * 32) + j];
            }

            printf("\n");
            printf("Signature: fake 2 %d\n", args->offset);
            for(int i = 0; i < 32; i++){
                shared_args->output_signature_list[args->offset * 32 + i] = SIGNATURES[K * Number_Of_Blocks * 32 + (args->total_blocks_index * 32) + i];
                // memcpy(shared_args->output_signature_list + args->offset * 32, SIGNATURES + (K * Number_Of_Blocks * 32 + (args->total_blocks_index * 32)), 32);
                printf("%X", SIGNATURES[K * Number_Of_Blocks * 32 + (args->total_blocks_index * 32) + i]);
            }
            printf("\n");
        pthread_mutex_unlock(&shared_args->lock);
    }
}

// typedef struct recoverable_block_indicies{
// 	int node_index;
// 	int internal_block_index;
// 	int code_word_number;
// 	int total_blocks_index;
// 	int is_corrupted;
// 	int is_local;
// }recoverable_block_indicies;

void ocall_retrieve_block(int fileNum, void *rb_indicies_ptr, NodeInfo *nodes, uint8_t *status, uint8_t *data_tmp, int block_size, int node_size, int rb_indicies_size)
{
    
    printf("RB 1");
    recoverable_block_indicies *rb_indicies = (recoverable_block_indicies *)rb_indicies_ptr;

    int k = K;
    int n = N;
    int symSize = 16;
    int m = n - k;

    pthread_t threads[N];

    ThreadSharedArgs *args = malloc(sizeof(ThreadSharedArgs));

    // args->output_code_word_buffer = malloc(N * BLOCK_SIZE * sizeof(uint8_t));
    // args->output_index_list = malloc(N * sizeof(uint8_t));
    args->output_code_word_buffer = data_tmp;
    args->output_index_list = malloc(N * sizeof(uint8_t));


    // INJA
    pthread_mutex_init(&args->lock, NULL);
    printf("RB 2");
    int i;
     for (i = 1; i < NUM_NODES; i++)
    {
        printf("RB 3");
        printf("this is the node index: %d\n", rb_indicies->node_index);
        printf("this is regular mode\n");
        ThreadWrapperArgs *wrapper_args = malloc(sizeof(ThreadWrapperArgs));
        if(rb_indicies->node_index == nodes[i].chunk_id){
            wrapper_args->fileNum = fileNum;
            wrapper_args->blockNum = rb_indicies[i].internal_block_index;
            wrapper_args->node_id = nodes[i].chunk_id;
            memcpy(wrapper_args->node_ip, nodes[i].ip, 16);
            wrapper_args->node_port = nodes[i].port;
            wrapper_args->shared_args = args;
            printf("this is the node ip: %s\n", nodes[i].ip);
            printf("this is the node port: %d\n", nodes[i].port);
            printf("this is the thread CREATTION OF : %d\n", i);
            pthread_create(&threads[0], NULL, request_data_from_node, wrapper_args);
            
            free(wrapper_args);
            break;
        }

    }

    printf("RB 4");

    if (rb_indicies->node_index >= NUM_NODES) {
        printf("RB 5");
        printf("this is the node index: %d\n", rb_indicies->node_index);
        printf("this is the fake mode\n");
        ThreadWrapperArgs *wrapper_args = malloc(sizeof(ThreadWrapperArgs));
        wrapper_args->fileNum = fileNum;
        wrapper_args->blockNum = 0;
        wrapper_args->node_id = 1;
        memcpy(wrapper_args->node_ip, nodes[1].ip, 16);
        wrapper_args->node_port = nodes[1].port;
        wrapper_args->shared_args = args;
        printf("this is the node ip: %s\n", nodes[1].ip);
        printf("this is the node port: %d\n", nodes[1].port);
        printf("this is the thread CREATTION OF : %d\n", 1);

        pthread_create(&threads[0], NULL, request_data_from_node, wrapper_args);

    }

    printf("RB 6");
    pthread_join(threads[i], NULL);

    printf("RB 7");
    memcpy(data_tmp, args->output_code_word_buffer, N * BLOCK_SIZE);
    // memcpy(code_word_index, args->output_index_list, N);
}

void ocall_get_batch_blocks(int fileNum, recoverable_block_indicies *rb_indicies, int rb_indicies_size, int rb_indicies_count, uint8_t *signatures, uint8_t *code_word, int *code_word_index, NodeInfo *nodes, int cw_size, int cw_count, int node_size)
{

    // recoverable_block_indicies *rb_indicies = (recoverable_block_indicies *)rb_indicies_ptr;

    printf("here is the broadcast block\n");
    int k = K;
    int n = N;
    int symSize = 16;
    int m = n - k;

    pthread_t threads[N];

    ThreadSharedArgs *args = malloc(sizeof(ThreadSharedArgs));
    ThreadSharedArgs *args_fake = malloc(sizeof(ThreadSharedArgs));

    args->output_code_word_buffer = malloc(N * BLOCK_SIZE * sizeof(uint8_t));
    memset(args->output_code_word_buffer, 0, N * BLOCK_SIZE);
    // this  list here used as signature list
    args->output_signature_list = malloc(N * 32);
    memset(args->output_signature_list, 0, N * 32);

    ThreadWrapperArgs *wrapper_args = malloc(N * sizeof(ThreadWrapperArgs));
    ThreadWrapperArgs *wrapper_args_fake = malloc(N * sizeof(ThreadWrapperArgs));




    pthread_mutex_init(&args->lock, NULL);

    int i;


    printf("this is the file num: %d\n", fileNum);
    printf("this is the node index: 1 : %d\n",  rb_indicies[0].node_index);
    printf("this is the node index: 2 : %d\n",  rb_indicies[1].node_index);
    printf("this is the node index: 3 : %d\n",  rb_indicies[2].node_index);
    printf("this is the node index: 4 : %d\n",  rb_indicies[3].node_index);
    printf("this is the node index: 5 : %d\n",  rb_indicies[4].node_index);


    printf("this is the is_local 1 : %d\n",  rb_indicies[0].is_local);
    printf("this is the is_local 2 : %d\n",  rb_indicies[1].is_local);
    printf("this is the is_local 3 : %d\n",  rb_indicies[2].is_local);
    printf("this is the is_local 4 : %d\n",  rb_indicies[3].is_local);
    printf("this is the is_local 5 : %d\n",  rb_indicies[4].is_local);

    printf("this is the total blocks index 1 : %d\n",  rb_indicies[0].total_blocks_index);
    printf("this is the total blocks index 2 : %d\n",  rb_indicies[1].total_blocks_index);
    printf("this is the total blocks index 3 : %d\n",  rb_indicies[2].total_blocks_index);
    printf("this is the total blocks index 4 : %d\n",  rb_indicies[3].total_blocks_index);
    printf("this is the total blocks index 5 : %d\n",  rb_indicies[4].total_blocks_index);


    int counter = 0;
    for (i = 0; i < K; i++)
    {
        printf("this is the i : %d\n", i);
        if(rb_indicies[i].is_local == 1){
            printf("this is the node index inside: %d\n", rb_indicies[i].node_index);
            continue;
        }
        printf("this is the node index outside: %d\n", rb_indicies[i].node_index);
        if(rb_indicies[i].node_index < NUM_NODES){


            printf("==============================================\n");
            printf("this is NORMAL turn: %d\n", i);
            printf("==============================================\n");
            for(int j = 0; j < NUM_NODES; j++){

                if(rb_indicies[i].node_index == nodes[j].chunk_id){
                    wrapper_args[counter].fileNum = fileNum;
                    wrapper_args[counter].blockNum = rb_indicies[i].internal_block_index;
                    wrapper_args[counter].total_blocks_index = rb_indicies[i].total_blocks_index;
                    wrapper_args[counter].node_id = nodes[j].chunk_id;
                    for(int k = 0; k < 16; k++) wrapper_args[counter].node_ip[k] = nodes[j].ip[k];
                    wrapper_args[counter].node_port = nodes[j].port;
                    wrapper_args[counter].shared_args = args;
                    wrapper_args[counter].fake = 0;
                    wrapper_args[counter].offset = i * BLOCK_SIZE;
                    pthread_create(&threads[counter], NULL, request_data_from_node, &wrapper_args[counter]);
                    counter++;

                }

            }
        }else{

            printf("==============================================\n");
            printf("this is FAKE turn: %d\n", i);
            printf("==============================================\n");

            // this is the fake node
            wrapper_args[counter].fileNum = fileNum;
            wrapper_args[counter].blockNum = 0;
            wrapper_args[counter].total_blocks_index = rb_indicies[i].total_blocks_index;
            wrapper_args[counter].node_id = nodes[1].chunk_id;
            wrapper_args[counter].offset = i;
            wrapper_args[counter].fake = 1;
            for(int k = 0; k < 16; k++) wrapper_args[counter].node_ip[k] = nodes[1].ip[k];
            wrapper_args[counter].node_port = nodes[1].port;
            wrapper_args[counter].shared_args = args;
            pthread_create(&threads[counter], NULL, request_data_from_node, &wrapper_args[counter]);
            counter++;

            // pthread_mutex_lock(&args->lock);    
            //     memcpy(args->output_code_word_buffer + i * BLOCK_SIZE, ALL_DATA + rb_indicies[i].total_blocks_index * BLOCK_SIZE, BLOCK_SIZE);
            // pthread_mutex_unlock(&args->lock);

        }
    }

    for(int i = K; i < N; i++){
            printf("==============================================\n");
            printf("this is Parity turn: %d\n", i);
            printf("==============================================\n");

            // this is the fake node
            wrapper_args[counter].fileNum = fileNum;
            wrapper_args[counter].blockNum = 0;
            wrapper_args[counter].total_blocks_index = rb_indicies[i].total_blocks_index;
            wrapper_args[counter].node_id = nodes[1].chunk_id;
            wrapper_args[counter].offset = i;
            wrapper_args[counter].fake = 2;
            for(int k = 0; k < 16; k++) wrapper_args[counter].node_ip[k] = nodes[1].ip[k];
            wrapper_args[counter].node_port = nodes[1].port;
            wrapper_args[counter].shared_args = args;
            pthread_create(&threads[counter], NULL, request_data_from_node, &wrapper_args[counter]);
            counter++;

            // pthread_mutex_lock(&args->lock);
            //     for(int j = 0; j < BLOCK_SIZE; j++){
            //         args->output_code_word_buffer[i * BLOCK_SIZE + j] = *((uint8_t *)(ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE) + j));
            //         // args->output_code_word_buffer[i * BLOCK_SIZE + j] = ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE) + j;
            //     }
            //     // memcpy(args->output_code_word_buffer + i * BLOCK_SIZE, ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE), BLOCK_SIZE);
            // pthread_mutex_unlock(&args->lock);

            // pthread_mutex_lock(&args->lock);

            // pthread_mutex_unlock(&args->lock);

    }
    
    for (int i = 0; i < counter; i++)
    {
        pthread_join(threads[i], NULL);
    }

    // uint8_t *buffer_total = malloc(N * BLOCK_SIZE * sizeof(uint8_t));


    // for(int i = K; i < N; i++){

    //     printf("==============================================\n");
    //     printf("this is Parity turn: %d\n", i);
    //     printf("==============================================\n");

    //     int tt = 0;

    //     for(int j = 0; j < BLOCK_SIZE; j++){
            
    //         args->output_code_word_buffer[i * BLOCK_SIZE + j] = ALL_DATA[K * Number_Of_Blocks * BLOCK_SIZE + (rb_indicies[i].total_blocks_index * BLOCK_SIZE) + j];

    //     }
    
        // memcpy(args->output_code_word_buffer + i * BLOCK_SIZE, ALL_DATA + (K * Number_Of_Blocks * BLOCK_SIZE) + (rb_indicies[i].total_blocks_index * BLOCK_SIZE), BLOCK_SIZE);
        
    // }

    

    memcpy(code_word, args->output_code_word_buffer, N * BLOCK_SIZE);
    memcpy(signatures, args->output_signature_list, N * 32);


    free(args->output_code_word_buffer);
    free(args->output_signature_list);
    free(wrapper_args);
    free(args);
    free(args_fake);
    free(wrapper_args_fake);
    return;

}

void ocall_get_rs_matrix(int k, int m, int symSize, int *matrix, int matrix_size)
{
    printf("k: %d, m: %d, symSize: %d, matrix_size: %d\n", k, m, symSize, matrix_size);
    // int *matrix = reed_sol_vandermonde_coding_matrix(K, N-K, symSize);

    int *rs_matrix = reed_sol_vandermonde_coding_matrix(k, m, symSize);
    printf("rs_matrix calculated\n");
    jerasure_print_matrix(rs_matrix, k, m, symSize);
    
    memcpy(matrix, rs_matrix, sizeof(int) * matrix_size);
    free(rs_matrix);
}

/**
 * @brief this function divides the file into K chunks and generates N - K parity chunks.
 * distributes the chunks to the nodes if the chunk is a parity chunk, it encrypts the chunk with the parity chunk encryption key
 * shares the key with the nodes securely. --Also it renames the file chunk0 to the current file name--
 * @param fileChunkName
 */
void initiate_Chunks(char *fileChunkName, char *current_file, int n, int k)
{

    char path[256];

    // divide the file into K chunks and generate N - K parity chunks. generated parities are stored in decentralize/chunks/chunk_i.bin
    initiate_rs(fileChunkName, k, n, Shuffle_key, 2);

    for (int i = 0; i < n; i++)
    {
        printf("i: %d\n", i);
        // 1. Open the file chunk_i.bin
        snprintf(path, sizeof(path), CHUNK_PATH_FORMAT, i);
        // printf("----------------------------File sending to node %d------------------------------\n", i);
        // printf("path: %s\n", path);
        FILE *fp = fopen(path, "rb");
        if (!fp)
        {
            perror("Failed to open chunk file");
            continue;
        }

        if (i == 0)
        {
            N = n;
            K = k;
            // if (strcmp(nodes[i].ip, current_ip) == 0) {

            Current_Chunk_ID = i;
            Number_Of_Blocks = get_file_size(fp) / BLOCK_SIZE;
            rename_file(path, current_file);
            // printf("Number of blocks: %d\n", Number_Of_Blocks);

            // TODO: set the is_parity_peer to 0 for the first node ( idea save the current node ip and compare)
            nodes[i].is_parity_peer = 0;

            continue;
        }

        // break;

        uint32_t chunk_type = 1; // 1 for data chunk, 2 for parity chunk
        uint32_t chunk_len;

        int sock;

        if (i > k) {chunk_type = 2;}
        else if (i < NUM_NODES){

        // get the size of the file
        chunk_len = get_file_size(fp);

        // 2. Create socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("Socket creation failed");
            fclose(fp);
            continue;
        }

        // 3. Connect to the ith node
        struct sockaddr_in server_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(nodes[i].port)};

        // printf("server_addr.sin_addr: %s\n", nodes[i].ip);
        // printf("server_addr.sin_port: %d\n", nodes[i].port);

        inet_pton(AF_INET, nodes[i].ip, &server_addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            perror("Connection to server failed");
            close(sock);
            fclose(fp);
            continue;
        }

        printf("Connected to node %d (%s:%d), sending file: %s\n", i, nodes[i].ip, nodes[i].port, path);

        // 4. Send the chunk type and length

        secure_send(sock, &Shuffle_key, sizeof(Shuffle_key));

        secure_send(sock, &N, sizeof(N));
        printf("N: %d\n", N);
        secure_send(sock, &K, sizeof(K));
        printf("K: %d\n", K);

        // send the chunk id
        secure_send(sock, &i, sizeof(int));

        // send the chunk type
        secure_send(sock, &chunk_type, sizeof(chunk_type));

        // send the chunk length
        secure_send(sock, &chunk_len, sizeof(chunk_len));
        // secure_send(sock, chunk, chunk_len);

        }
        // 4. Send file in chunks
        uint8_t *complete_buffer = malloc(chunk_len * sizeof(uint8_t));
        memset(complete_buffer, 0, chunk_len);
        size_t bytes_read;

        if (i > K)
        { // parity chunks
            printf("parity chunk\n");
            uint8_t buffer[BLOCK_SIZE];

            // shuffle the file
            int num_bits = ceil(log2(Number_Of_Blocks));
            for (int j = 0; j < Number_Of_Blocks; j++)
            {
                uint64_t permuted_index = feistel_network_prp(Shuffle_key, j, Number_Of_Blocks * (N -K));
                while(permuted_index >= Number_Of_Blocks * (N -K)){
                    permuted_index = feistel_network_prp(Shuffle_key, permuted_index, Number_Of_Blocks * (N -K));
                }
                bytes_read = fread(buffer, 1, BLOCK_SIZE, fp);
                memcpy(complete_buffer + (permuted_index * BLOCK_SIZE), buffer, bytes_read);
                // offset += bytes_read;
            }

            for (int i = 0; i < Number_Of_Blocks; i++)
            {
                memcpy(buffer, complete_buffer + (i * BLOCK_SIZE), BLOCK_SIZE);

                EncryptData2(PC_KEY, buffer, BLOCK_SIZE);

                // ssize_t sent = secure_send(sock, buffer, BLOCK_SIZE);
                // if (sent < 0)
                // {
                //     perror("Send failed");
                //     break;
                // }
            }
        }
        else if (i < NUM_NODES)
        { // data chunks
            printf("data chunk\n");
            uint8_t buffer[CHUNK_BUFFER_SIZE];
            while ((bytes_read = fread(buffer, 1, CHUNK_BUFFER_SIZE, fp)) > 0)
            {
                ssize_t sent = secure_send(sock, buffer, bytes_read);
                if (sent < 0)
                {
                    perror("Send failed");
                    break;
                }
            }
        }

        printf("-----------------------------------------------------------\n");
        printf("File %s sent to node %d\n", path, i);
        printf("-----------------------------------------------------------\n");
        free(complete_buffer);
        close(sock);
        fclose(fp);
    }
}

// void ocall_request_data_chunk(uint8_t nodeID, uint32_t blockID, uint8_t *output_buffer, size_t *actual_len, size_t buf_len) {
//     if (nodeID >= NUM_NODES || !nodes[nodeID].is_ready) {
//         printf("Node %d is not ready\n", nodeID);
//         *actual_len = 0;
//         return;
//     }

//     TransferThreadArgs *args = malloc(sizeof(TransferThreadArgs));
//     if (!args) {
//         printf("Memory allocation failed\n");
//         *actual_len = 0;
//         return;
//     }

//     args->nodeID = nodeID;
//     args->blockID = blockID;
//     args->output_buffer = output_buffer;
//     args->output_len_ptr = actual_len;
//     args->buf_len = buf_len;

//     pthread_t thread;
//     // if (pthread_create(&thread, NULL, transfer_chunk_thread_func, args) != 0) {
//     //     printf("Failed to create thread\n");
//     //     free(args);
//     //     *actual_len = 0;
//     //     return;
//     // }

//     pthread_join(thread, NULL);  // Block until it's done (you can detach instead)
// }

void connection_thread_func(void *args_ptr)
{

    ThreadArgs *args = (ThreadArgs *)args_ptr;

    
}

void ocall_peer_init(uint8_t *current_pubKey, uint8_t *peer_pubKey, const char *ip, int port, int current_id, int *peer_id)
{

    // 1. Create and connect the socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        printf("Socket creation failed for ip %s\n", ip);
        return;
    }


    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    printf("ip: %s\n", ip);
    printf("port: %d\n", port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0)
    {
        printf("Invalid IP for ip %s\n", ip);
        close(socket_fd);
        return;
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Connection failed for ip %s\n", ip);
        close(socket_fd);
        return;
    }

    printf("socket_fd: %d\n", socket_fd);
    printf("current_id: %d\n", current_id);
    printf("current_pubKey: %s\n", current_pubKey);
    printf("peer_pubKey: %s\n", peer_pubKey);
    printf("ip: %s\n", ip);
    printf("port: %d\n", port);

    RequestType type = INIT;

    printf("RequestType: %d\n", type);
    secure_send(socket_fd, &type, sizeof(RequestType));

    // send the current id
    if (secure_send(socket_fd, &current_id, sizeof(current_id)) != sizeof(current_id))
    {
        printf("Failed to send current id to ip %s\n", ip);
        close(socket_fd);
        return;
    }

    // 2. Exchange public keys
    if (secure_send(socket_fd, current_pubKey, PUB_SIZE) != PUB_SIZE)
    {
        printf("Failed to send host pubKey to ip %s\n", ip);
        close(socket_fd);
        return;
    }

    if (secure_recv(socket_fd, peer_pubKey, PUB_SIZE) != PUB_SIZE)
    {
        printf("Failed to receive guest pubKey from ip %s\n", ip);
        close(socket_fd);
        return;
    }

    int peer_id_tmp;    
    if (secure_recv(socket_fd, &peer_id_tmp, sizeof(int)) != sizeof(int))
    {
        printf("Failed to receive peer id from ip %s\n", ip);
        close(socket_fd);
        return;
    }
    printf("##############################Recv peer_id################################\n");
    printf("recieved from: %d\n", port);
    printf("recived from ip: %s\n", ip);
    printf("recievedpeer_id: %d\n", peer_id_tmp);
    printf("##############################&&&&&&&&&&&&################################\n");
    *peer_id = peer_id_tmp;

    // 4. Mark node as ready
    printf("-------------------------------------------------------\n");
    printf("The IP %s connected and session key initialized with socket ID%d and peer pubKey %s\n", ip, socket_fd, peer_pubKey);
    printf("-------------------------------------------------------\n");

    ack_send(socket_fd);

    // 5. Close the socket
    close(socket_fd);
}

/**

void* transfer_chunk_thread_func(void *args_ptr) {
    TransferThreadArgs *args = (TransferThreadArgs *)args_ptr;
    uint8_t nodeID = args->nodeID;
    uint32_t blockID = args->blockID;
    uint8_t *output_buffer = args->output_buffer;
    size_t *output_len_ptr = args->output_len_ptr;
    size_t buf_len = args->buf_len;
    free(args);  // We can free this, enclave buffer remains

    if (nodeID >= NUM_NODES || !nodes[nodeID].is_ready) {
        printf("Node %d is not ready\n", nodeID);
        *output_len_ptr = 0;
        return NULL;
    }

    int sock = nodes[nodeID].socket_fd;

    // Send request
    char msg[64];
    snprintf(msg, sizeof(msg), "BLOCK:%u", blockID);
    send(sock, msg, strlen(msg), 0);

    // Receive encrypted data
    uint8_t encrypted_data[BLOCK_SIZE];
    ssize_t received = recv(sock, encrypted_data, sizeof(encrypted_data), 0);
    if (received <= 0 || received > buf_len) {
        printf("Receive failed or buffer too small\n");
        *output_len_ptr = 0;
        return NULL;
    }

    // Copy received encrypted data into enclave buffer
    memcpy(output_buffer, encrypted_data, received);
    *output_len_ptr = received;

    return NULL;
}
*/

// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------
//                                 main functions
#include <errno.h>


void get_my_ip(char *ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        return;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);  // arbitrary port
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sock, (struct sockaddr *)&local_addr, &addr_len);

    // Now fill the caller's buffer (not a new local one!)
    inet_ntop(AF_INET, &local_addr.sin_addr, ip, INET_ADDRSTRLEN);

    close(sock);
}




void preprocessing(sgx_enclave_id_t eid, int mode, char *fileChunkName, FileDataTransfer *fileDataTransfer, int n, int k)
{

    init_keys();

    // make the directory for the chunks
    if (mkdir("App/decentralize/chunks", 0755) == 0)
    {
        printf("Folder created successfully.\n");
    }
    else
    {
        if (errno == EEXIST)
        {
            printf("Folder already exists.\n");
        }
        else
        {
            fprintf(stderr, "mkdir failed: %s\n", strerror(errno));
        }
    }

    // the stored file name for local peer
    char *current_file = "App/decentralize/chunks/current_file.bin";

    if (mode == 1)
    {
        // reciever mode

        printf("+++mode 1 started+++\n");
        reciever_data_initialization(current_file);
        printf("+++mode 1 finished+++\n");
    }
    else if (mode == 2)
    {
        // performer mode
        printf("+++mode 2 started+++\n");
        initiate_Chunks(fileChunkName, current_file, n, k);
        printf("+++mode 2 finished+++\n");
    }

    // initialize the fileDataTransfer
    fileDataTransfer->numBlocks = Number_Of_Blocks;
    //    fileDataTransfer->nodes = nodes;
    memcpy(fileDataTransfer->nodes, nodes, sizeof(NodeInfo) * NUM_NODES);

    fileDataTransfer->n = N;
    fileDataTransfer->k = K;
    strncpy(fileDataTransfer->fileName, current_file, sizeof(fileDataTransfer->fileName) - 1);
    fileDataTransfer->fileName[sizeof(fileDataTransfer->fileName) - 1] = '\0';
    //    strcpy(fileDataTransfer->fileName, current_file);
    //    fileDataTransfer->fileName = current_file;
    printf("**************************************************");
    printf("Current_Chunk_ID: %d\n", Current_Chunk_ID);
    printf("**************************************************");
    fileDataTransfer->current_id = Current_Chunk_ID;



    char current_ip[INET_ADDRSTRLEN];
    int current_port = 8080;

    get_my_ip(current_ip);

    strncpy(fileDataTransfer->current_ip, current_ip, INET_ADDRSTRLEN);
    fileDataTransfer->current_ip[INET_ADDRSTRLEN - 1] = '\0';  // ensure null-termination

    fileDataTransfer->current_port = current_port;



    strncpy(fileDataTransfer->owner_ip, nodes[0].ip, INET_ADDRSTRLEN);
    fileDataTransfer->owner_ip[INET_ADDRSTRLEN - 1] = '\0';  // ensure null-termination

    fileDataTransfer->owner_port = nodes[0].port;

    

    //    strcpy(fileChunkName, current_file);
    //    fileChunkName = current_file;

    // ------------------------------------------------------------------------------
    //                                 rest of the code for all modes

    pthread_t listener_thread;
    sgx_enclave_id_t *eid_ptr = malloc(sizeof(sgx_enclave_id_t));
    // the reason for this is that the pthread_create only accepts pointer
    *eid_ptr = eid;
    if (pthread_create(&listener_thread, NULL, listener_thread_func, eid_ptr) != 0)
    {
        perror("Failed to create listener thread");
        free(eid_ptr);
        return 1;
    }
    pthread_detach(listener_thread);


    ecall_set_currentID(eid,Current_Chunk_ID);

    // // Generate a random K x N matrix A
    // int A[K][N];
    // for (int i = 0; i < K; i++) {
    //     for (int j = 0; j < N; j++) {
}



void load_file_data(char *file_name, int num_blocks, int mode , int k , int n, sgx_enclave_id_t eid) {


    if (mode == 1){
        initiate_rs(file_name, k, n, Shuffle_key, mode);
    }

    int num_bits = ceil(log2(Number_Of_Blocks * K));

    int permuted_index_0 = permutation(0, num_bits, Number_Of_Blocks * (K));

    int chunk_size = num_blocks * BLOCK_SIZE;

    ALL_DATA = malloc(BLOCK_SIZE * n * sizeof(uint8_t) * Number_Of_Blocks);
    SIGNATURES = malloc(32 * n * sizeof(uint8_t) * Number_Of_Blocks);




    char file_path[256];
    if (mode == 2){
        snprintf(file_path, sizeof(file_path), "App/decentralize/chunks/current_file.bin");
    }else if (mode == 1){
        snprintf(file_path, sizeof(file_path), "App/decentralize/NF/data_0.dat");
    }

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }


    for (int j = 0; j < num_blocks; j++){
        printf("this is the block %d\n", j);
        uint8_t *buffer = malloc(BLOCK_SIZE);

        if(fread(buffer, 1, BLOCK_SIZE, file) != BLOCK_SIZE) {
            perror("Failed to read file");
            fclose(file);
            free(ALL_DATA);
            return;
        }
        
        printf("\n");
        uint8_t *buffer2 = malloc(BLOCK_SIZE);
        memcpy(buffer2, buffer, BLOCK_SIZE);
        EncryptData2(PC_KEY, buffer2, BLOCK_SIZE);

        ssize_t size = 32;
        uint8_t *buffer3 = malloc(BLOCK_SIZE);
        
        memcpy(buffer3, buffer2, BLOCK_SIZE);
        hmac_sha2(sig_key, 32, (const uint8_t *)buffer3, BLOCK_SIZE, (uint8_t *)SIGNATURES + j * 32, &size);

        printf("\n");
        memcpy(ALL_DATA + j * BLOCK_SIZE, buffer2, BLOCK_SIZE);
        free(buffer);
        free(buffer2);
        free(buffer3);
    }

    
    printf("=== Preprocessing started === %s\n", file_path);
    fclose(file);

    for(int i = 1; i < k; i++) {
        char chunk_path[256];  // allocate space
        if (mode == 2){
            snprintf(chunk_path, sizeof(chunk_path), CHUNK_PATH_FORMAT, i);
        }else if (mode == 1){
            snprintf(chunk_path, sizeof(chunk_path), CHUNK_PATH_FORMAT2, i);
        }
        FILE *chunk_file = fopen(chunk_path, "rb");
        if (!chunk_file) {
            perror("Failed to open chunk file");
            free(ALL_DATA);
            return;
        }
        for(int j = 0; j < num_blocks; j++){
            uint8_t *buffer = malloc(BLOCK_SIZE);
            if(fread(buffer, 1, BLOCK_SIZE, chunk_file) != BLOCK_SIZE) {
                perror("Failed to read chunk file");
                fclose(chunk_file);
                free(ALL_DATA);
                return;
            }
            printf("\n");
            uint8_t *buffer2 = malloc(BLOCK_SIZE);
            memcpy(buffer2, buffer, BLOCK_SIZE);
            EncryptData2(PC_KEY, buffer2, BLOCK_SIZE);

            ssize_t size = 32;
            uint8_t *buffer3 = malloc(BLOCK_SIZE);

            memcpy(buffer3, buffer2, BLOCK_SIZE);
            hmac_sha2(sig_key, 32, (const uint8_t *)buffer3, BLOCK_SIZE, (uint8_t *)SIGNATURES + i * num_blocks * 32 + j * 32, &size);

            memcpy(ALL_DATA + i * chunk_size + j * BLOCK_SIZE, buffer2, BLOCK_SIZE);
            free(buffer);
            free(buffer2);
            free(buffer3);
        }
        fclose(chunk_file);
    }

    int num_bits2 = ceil(log2((N - K) * Number_Of_Blocks));
    // this is for parity chunks
    for(int o = K; o < N; o++) {
        char chunk_path[256];  // allocate space
        if (mode == 2){
            snprintf(chunk_path, sizeof(chunk_path), CHUNK_PATH_FORMAT, o);
            printf("this is the chunk path: %s\n", chunk_path);
        }else if (mode == 1){
            snprintf(chunk_path, sizeof(chunk_path), CHUNK_PATH_FORMAT2, o);
        }
        FILE *chunk_file = fopen(chunk_path, "rb");
        if (!chunk_file) {
            perror("Failed to open chunk file");
            free(ALL_DATA);
            return;
        }


        for (int j = 0; j < Number_Of_Blocks; j++)
        {
            uint8_t *buffer = malloc(BLOCK_SIZE);

            int permuted_index = permutation((Number_Of_Blocks * (o - K) )+ j, num_bits2, Number_Of_Blocks * (N -K));
            printf("this is the i %d and the permuted index: %d\n", (Number_Of_Blocks * (o - K) )+ j, permuted_index);

            if(fread(buffer, 1, BLOCK_SIZE, chunk_file) != BLOCK_SIZE) {
                perror("Failed to read chunk file");
                fclose(chunk_file);
                free(ALL_DATA);
                return;
            }

            uint8_t *buffer2 = malloc(BLOCK_SIZE);
            memcpy(buffer2, buffer, BLOCK_SIZE);
            EncryptData2(PC_KEY, buffer2, BLOCK_SIZE);


            ssize_t size = 32;
            uint8_t *buffer3 = malloc(BLOCK_SIZE);

            memcpy(buffer3, buffer2, BLOCK_SIZE);
            hmac_sha2(sig_key, 32, (const uint8_t *)buffer3, BLOCK_SIZE, (uint8_t *)SIGNATURES + o * num_blocks * 32 + j * 32, &size);


            memcpy(ALL_DATA + (K * chunk_size) + (permuted_index * BLOCK_SIZE), buffer2, BLOCK_SIZE);


            // printf("this is block %d\n", permuted_index);
            // for(int k = 0; k < 40; k++){
            //     printf("%X ", ALL_DATA + (K * chunk_size) + (permuted_index * BLOCK_SIZE) + k);
            // }
            // printf("\n--------------------------------\n");
            // uint8_t buffer21[BLOCK_SIZE];
            // memcpy(buffer21, ALL_DATA + (K * chunk_size) + (permuted_index * BLOCK_SIZE), BLOCK_SIZE);
            // DecryptData2(PC_KEY, buffer21, BLOCK_SIZE);
            // printf("this is the buffer2: %d\n", j);
            // for(int k = 0; k < 40; k++){
            //     printf("%X ", buffer21[k]);
            // }
            // printf("\n--------------------------------\n");

            free(buffer);
            free(buffer2);
            free(buffer3);

        }

            



        fclose(chunk_file);
    }

    printf("Number of blocks: %d\n", Number_Of_Blocks);
    printf("Number of parity blocks: %d\n", N - K);
    printf("Number of total blocks: %d\n", N);
    // for(int i = K * Number_Of_Blocks; i < N * Number_Of_Blocks; i++){

    //     printf("this is the block %d\n", i);
    //     for(int j = 0; j < 4096; j++){
    //         printf("%X", ALL_DATA[i * 4096 + j]);
    //     }
    //     printf("\n");
    // }

    // for(int i = 0; i < N * Number_Of_Blocks; i++){
    //     uint8_t *buffer = malloc(BLOCK_SIZE);
    //     memcpy(buffer, ALL_DATA + i * BLOCK_SIZE, BLOCK_SIZE);
    //     DecryptData2(PC_KEY, buffer, BLOCK_SIZE);
    //     printf("this is the block %d\n", i);
    //     for(int j = 0; j < 32; j++){
    //         printf("%X", buffer[j]);
    //     }
    //     printf("\n");
    // }


    // for(int i = 0; i < N * Number_Of_Blocks; i++){
    //     printf("this is the signature %d\n", i);
    //     for(int j = 0; j < 32; j++){
    //         printf("%X", SIGNATURES[i * 32 + j]);
    //     }
    //     printf("\n");
    // }




}


