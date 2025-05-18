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

#include "../rs/rs.h"
#include "../aes/aes.h"
#define N 5
#define K 3
int Number_Of_Blocks;
int Current_Chunk_ID;

// define all the types that reciver can accept
typedef enum {
    INIT = 0,
    CHUNK = 1,
    PARITY_KEY = 2,
    BLOCK = 3
} RequestType;



NodeInfo nodes[NUM_NODES] = {
    {"192.168.1.1", 8080, -1, 0}, // This is the host node do not count it as a node
    {"141.219.210.172", 8080, -1, 0},
    // {"192.168.1.2", 8081, -1, 0},
    // {"192.168.1.3", 8082, -1, 0}
};

typedef struct {
    uint8_t nodeID;
    uint32_t blockID;
    uint8_t *output_buffer;
    size_t *output_len_ptr;
    size_t buf_len;
} TransferThreadArgs;

typedef struct {
    uint8_t *current_pubKey;
    uint8_t *peer_pubKey;
    char *ip;
    int port;
    int *socket_fd;
    int current_id;
} ThreadArgs;



#define CHUNK_PATH_FORMAT "App/decentralize/chunks/data_%d.dat"
#define CHUNK_BUFFER_SIZE 1024

// Parity chunk encryption key
uint8_t PC_KEY[32];
uint8_t Shuffle_key[KEY_SIZE];



// ------------------------------------------------------------------------------
//                                 helper functions

void init_keys(){

    uint32_t seed;
    RAND_bytes((unsigned char*)&seed, sizeof(seed));  // 32 bits of entropy
    prng_init(seed);
    for (int i = 0; i < 32; i++) {
        PC_KEY[i] = prng_next();
    }

    // generate the shuffle key
    RAND_bytes(Shuffle_key, KEY_SIZE);
}

/**
 * @brief this function receives data securely from the server
 * @param sock the socket file descriptor
 * @param buf the data to receive
 * @param len the length of the data to receive
 * @return the number of bytes received
 */
ssize_t secure_recv(int sock, void *buf, size_t len) {
    size_t total_received = 0;
    char *data = (char *)buf;

    while (total_received < len) {
        ssize_t received = recv(sock, data + total_received, len - total_received, 0);
        if (received < 0) {
            perror("Receive failed");
            return -1; // Error occurred
        }
        if (received == 0) {
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
int EncryptData(uint32_t* KEY,void* buffer, int dataLen)
{
    //encrypt before writing
    AesCtx ctx;
    unsigned char iv[] = "1234";
    //unsigned char key[] = "876543218765432";
    unsigned char key[16];    
    uint8_t i;
    for(i=0;i<4;i++){    
     key[4*i]=(*(KEY+i))/NUM1;
     key[(4*i)+1]=((*(KEY+i))/NUM2)%NUM3;
     key[(4*i)+2]=(*(KEY+i)% NUM2)/NUM3;
     key[(4*i)+3]=(*(KEY+i)% NUM2)%NUM3;
    }
    for(i=0;i<16;i++){ 
     // uart_printf("EncryptData():the %d byte of key is %x\n\r",i,key[i]); 
    }
    
    //uart_printf("before encrypt: %s\n\r", buffer);
    
   // initialize context and encrypt data at one end    
    if( AesCtxIni(&ctx, iv, key, KEY128, EBC) < 0) {
        //uart_printf("init error\n");
	}

    
    int flag = 0;
    if ((flag = AesEncrypt(&ctx, (unsigned char *)buffer, (unsigned char *)buffer, dataLen)) < 0) 
      // dataLen needs to be different based on PDP vs ECC. Full 512 byte segment for ECC. KEY_SIZE for PDP.
    {
       //uart_printf("error in encryption\n");
       if(flag == -2)
      {
        //uart_printf("Data is empty");
        //return -2;
      }
      else if(flag == -3)
      {
        //uart_printf("cipher is empty");
      //return -3;
      }
      else if(flag == -4)
      {
        //uart_printf("context is empty");
       // return -4;
      }
      else if(flag == -5)
      {
        //uart_printf("data length is not a multiple of 16");
      //return -5;
      }
      else
      {
        //uart_printf("other error");
      }    
    }else{
      //uart_printf("encryption ok %d\n\r",count_write);
      //uart_printf("after encrypt: %s\n\r", buffer);      
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
ssize_t secure_send(int sock, const void *buf, size_t len) {
    size_t total_sent = 0;
    const char *data = (const char *)buf;

    while (total_sent < len) {
        ssize_t sent = send(sock, data + total_sent, len - total_sent, 0);
        if (sent < 0) {
            perror("Send failed");
            return -1; // Error occurred
        }
        total_sent += sent;
    }
    return total_sent; // All data sent successfully
}


void* listener_thread_func(sgx_enclave_id_t eid) {
    int server_socket = setup_server_socket();
    if (server_socket < 0) {
        printf("Failed to setup server socket\n");
        return NULL;
    }


    while (1) {

        printf("Waiting for client connection...\n");
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);

        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        handle_client(eid, client_socket);  // or create another thread for each client
    }

    return NULL;
}

/**
 * @brief this functin recieve first the file type and then the file size and then the file data
 * @param client_socket the client socket 
 * @param save_path the path to save the file
 * @return the file path
 */
char* store_received_file(int client_socket, char* save_path) {

    u_int32_t file_size;
    u_int32_t file_type;
    int chunk_id;

    FILE *fp = fopen(save_path, "wb");
    if (!fp) {
        perror("Failed to open file for writing");
        return NULL;
    }

    uint8_t buffer[1024];
    ssize_t len;

    // receive the file type and size
    secure_recv(client_socket, &chunk_id, sizeof(int));
    secure_recv(client_socket, &file_type, sizeof(file_type));
    secure_recv(client_socket, &file_size, sizeof(file_size));

    Current_Chunk_ID = chunk_id;
    // while ((len = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
    // while ((len = secure_recv(client_socket, buffer, file_size)) > 0) {
    for (size_t i = 0; i < file_size/CHUNK_BUFFER_SIZE; i++)
    {
        len = secure_recv(client_socket, buffer, CHUNK_BUFFER_SIZE);
        printf("this is the %d th len: %d\n", i, len);
        fwrite(buffer, 1, len, fp);

    }

    Number_Of_Blocks = file_size/BLOCK_SIZE;

    // if (file_type == 2) {
    //     secure_recv(client_socket, PC_KEY_received, 16);
    // }


    fclose(fp);

    if (len < 0) {
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
static long get_file_size(FILE *file){
    fseek(file, 0 ,SEEK_END);
    long size = ftell(file);
    rewind(file);
    return size;
}



/**
 * @brief this function sets up the server socket on port 8080
 * @return the server socket file descriptor
 */
int setup_server_socket() {

    int port = 8080;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return -1;
    }

    // Allow port reuse
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 10) < 0) {
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
int rename_file(const char* old_name, const char* new_name) {
    if (rename(old_name, new_name) == 0) {
        printf("File renamed successfully from '%s' to '%s'.\n", old_name, new_name);
        return 0; // success
    } else {
        perror("Error renaming file");
        return -1;
    }
}
// ------------------------------------------------------------------------------
//                                 Receiver functions

void ocall_get_shuffle_key( u_int8_t *Shuffle_key, u_int8_t *Kexchange_PUB_KEY, u_int8_t *Kexchange_DataOwner_PUB_KEY, u_int8_t *PARITY_AES_KEY, char *owner_ip, int owner_port) {
    // printf("Shuffle key: %s\n", Shuffle_key);
    printf("Owner IP: %s\n", owner_ip);
    printf("Owner Port: %d\n", owner_port);

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(owner_port)
    };

    inet_pton(AF_INET, owner_ip, &server_addr.sin_addr);

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(client_socket);
        return;
    }

    secure_send(client_socket, PARITY_KEY, sizeof(RequestType));

    // ------------------------------------------------------------
    // |             need to be done for attestation               |
    // |                         Decap                             |
    // ------------------------------------------------------------
    // ecall_get_report(eid, pub_key, quote, quote_size);
    // uint8_t quote[1024];
    // uint32_t quote_size;

    secure_send(client_socket, Kexchange_PUB_KEY, 64);
    
    secure_recv(client_socket, Kexchange_DataOwner_PUB_KEY, 64);

    secure_recv(client_socket, Shuffle_key, KEY_SIZE);

    secure_recv(client_socket, PARITY_AES_KEY, 64);

    close(client_socket);
}

void reciever_data_initialization(char* fileChunkName) {
    int server_socket = setup_server_socket();
    printf("Waiting for the client file...\n");

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
    if (client_socket < 0) {
        perror("Accept failed");
        return;
    }

    // const char *filename = "received_file.bin";
    // char received_path[PATH_MAX];
    // snprintf(received_path, sizeof(received_path), "/tmp/%s", filename);

    char *stored_path = store_received_file(client_socket, fileChunkName);
    if (stored_path) {
        printf("File received and saved at: %s\n", stored_path);

        // You can now use `stored_path` wherever needed

        free(stored_path);
    }

    close(client_socket);
    close(server_socket);
}


void initialize_peer2peer_connection(sgx_enclave_id_t eid, int client_socket) {

    int sender_id;
    uint8_t sender_pubKey[PUB_SIZE];
    uint8_t current_pubKey[PUB_SIZE];

    secure_recv(client_socket, &sender_id, sizeof(sender_id));
    secure_recv(client_socket, sender_pubKey, PUB_SIZE);

    // get the sender ip and port
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if (getpeername(client_socket, (struct sockaddr *)&addr, &addr_len) == -1) {
        perror("getpeername failed");
        return;
    }

    char ip_str[INET_ADDRSTRLEN]; // enough for IPv4
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));

    int port = ntohs(addr.sin_port);

    printf("Client IP: %s\n", ip_str);
    printf("Client Port: %d\n", port);


    ecall_peer_init(eid, current_pubKey, sender_pubKey, ip_str, &client_socket, sender_id);

    secure_send(client_socket, current_pubKey, PUB_SIZE);
    
    

}

// #include <sgx_dcap_quoteverify.h>
// #include <openssl/sha.h>

// the owner of data he needs to make sure the key requested from TEE is correct
void handle_key_exchange(sgx_enclave_id_t eid, int client_socket) {



    uint8_t Requester_PUB_KEY[PUB_SIZE];

    uint8_t Kexchange_DataOwner_PUB_KEY[64];
    uint8_t Kexchange_DataOwner_prv_KEY[32];

    uint8_t sharedKey[32];

    uint32_t seed;
    RAND_bytes((unsigned char*)&seed, sizeof(seed));  // 32 bits of entropy
    prng_init(seed);
    for (int i = 0; i < 32; i++) {
        Kexchange_DataOwner_prv_KEY[i] = prng_next();
    }

    ecdh_generate_keys(Kexchange_DataOwner_PUB_KEY, Kexchange_DataOwner_prv_KEY);


    char owner_ip[INET_ADDRSTRLEN];
    int owner_port;


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

    secure_recv(client_socket, Requester_PUB_KEY, PUB_SIZE);

    secure_send(client_socket, Kexchange_DataOwner_PUB_KEY, PUB_SIZE);

    ecdh_shared_secret(Kexchange_DataOwner_prv_KEY, Requester_PUB_KEY, sharedKey);

    uint8_t Shuffle_key_tmp[KEY_SIZE];
    uint8_t PC_KEY_tmp[32];

    memcpy(Shuffle_key_tmp, Shuffle_key, KEY_SIZE);
    memcpy(PC_KEY_tmp, PC_KEY, 32);

    EncryptData(sharedKey, Shuffle_key_tmp, KEY_SIZE);
    EncryptData(sharedKey, PC_KEY_tmp, 32);

    secure_send(client_socket, Shuffle_key_tmp, KEY_SIZE);
    secure_send(client_socket, PC_KEY_tmp, 32);

    close(client_socket);
}


void handle_client(sgx_enclave_id_t eid, int client_socket) {

    // Reciever side
    printf("Client connected\n");

    while (1) {

        uint8_t type;
        ssize_t len = recv(client_socket, &type, sizeof(type), 0);

        RequestType request = (RequestType)type;

        if (len <= 0) break; // client disconnected

        if (request == INIT){
            printf("Initialization request received\n");
            initialize_peer2peer_connection(eid, client_socket);
        }else if(request == CHUNK) {
            printf("Chunk request received\n");
        }else if(request == PARITY_KEY) {
            printf("Parity request received\n");
            // for the key exchange we need attestation
            handle_key_exchange(eid, client_socket);
        }else if(request == BLOCK) {
            printf("Block request received\n");
        }else {
            printf("Unknown request received\n");
        }


    }

    close(client_socket);
}





// ------------------------------------------------------------------------------
//                                 Sender functions

/**
 * @brief this function divides the file into K chunks and generates N - K parity chunks. 
 * distributes the chunks to the nodes if the chunk is a parity chunk, it encrypts the chunk with the parity chunk encryption key
 * shares the key with the nodes securely. --Also it renames the file chunk0 to the current file name--
 * @param fileChunkName 
 */
void initiate_Chunks(char* fileChunkName, char* current_file) {
    
    char path[256];

    // divide the file into K chunks and generate N - K parity chunks. generated parities are stored in decentralize/chunks/chunk_i.bin
    initiate_rs(fileChunkName, K, N);



    for (int i = 0; i < NUM_NODES ; i++) {


        // 1. Open the file chunk_i.bin
        snprintf(path, sizeof(path), CHUNK_PATH_FORMAT, i);
        printf("----------------------------File sending to node %d------------------------------\n", i);
        printf("path: %s\n", path);
        FILE *fp = fopen(path, "rb");
        if (!fp) {
            perror("Failed to open chunk file");
            continue;
        }

        if (i == 0) {
        // if (strcmp(nodes[i].ip, current_ip) == 0) {

            Current_Chunk_ID = i;
            Number_Of_Blocks = get_file_size(fp)/BLOCK_SIZE;
            rename_file(path, current_file);
            printf("Number of blocks: %d\n", Number_Of_Blocks);

            //TODO: set the is_parity_peer to 0 for the first node ( idea save the current node ip and compare)
            nodes[i].is_parity_peer = 0;

            continue;
        } 

        // TODO: remove this break
        break;


        uint32_t chunk_type = 1; // 1 for data chunk, 2 for parity chunk
        uint32_t chunk_len;

        if (i > K) chunk_type = 2;

        

        // get the size of the file
        chunk_len = get_file_size(fp);


        // 2. Create socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            fclose(fp);
            continue;
        }


        // 3. Connect to the ith node
        struct sockaddr_in server_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(nodes[i].port)
        };

        printf("server_addr.sin_addr: %s\n", nodes[i].ip);
        printf("server_addr.sin_port: %d\n", nodes[i].port);

        inet_pton(AF_INET, nodes[i].ip, &server_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection to server failed");
            close(sock);
            fclose(fp);
            continue;
        }

        printf("Connected to node %d (%s:%d), sending file: %s\n", i, nodes[i].ip, nodes[i].port, path);

        // 4. Send the chunk type and length

        // send the chunk id
        secure_send(sock, &i, sizeof(int));
        
        // send the chunk type
        secure_send(sock, &chunk_type, sizeof(chunk_type));
        
        // send the chunk length
        secure_send(sock, &chunk_len, sizeof(chunk_len));
        // secure_send(sock, chunk, chunk_len);     

        // 4. Send file in chunks
        uint8_t *complete_buffer = malloc(chunk_len * sizeof(uint8_t));
        memset(complete_buffer, 0, chunk_len);
        uint8_t buffer[CHUNK_BUFFER_SIZE];
        size_t bytes_read;

        uint8_t Shuffle_key[KEY_SIZE];

        RAND_bytes(Shuffle_key, KEY_SIZE);


        if (i > K) { // parity chunks

        // shuffle the file
            int num_bits = ceil(log2(Number_Of_Blocks));
            for (int j = 0; j < Number_Of_Blocks; j++) {
                // we need to generate key for shuffle
                uint64_t j2 = feistel_network_prp(Shuffle_key, j, num_bits);
                bytes_read = fread(buffer, 1, 4096, fp);
                memcpy(complete_buffer + (j2 * 4096), buffer, bytes_read);
                // offset += bytes_read;
            }

            for (int i = 0; i < Number_Of_Blocks * 4; i++)
            {
                memcpy(buffer, complete_buffer + (i * CHUNK_BUFFER_SIZE), CHUNK_BUFFER_SIZE);

                EncryptData(PC_KEY, buffer, bytes_read);

                ssize_t sent = secure_send(sock, buffer, bytes_read);
                if (sent < 0) {
                    perror("Send failed");
                    break;
                }
            }
            

        }else{ // data chunks
            while ((bytes_read = fread(buffer, 1, CHUNK_BUFFER_SIZE, fp)) > 0) {
                ssize_t sent = secure_send(sock, buffer, bytes_read);
                if (sent < 0) {
                    perror("Send failed");
                    break;
                }
            }
        }



        printf("-----------------------------------------------------------\n");
        printf("File %s sent to node %d\n", path, i);
        printf("-----------------------------------------------------------\n");


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


void* connection_thread_func(void *args_ptr) {

    ThreadArgs *args = (ThreadArgs *)args_ptr;

    int current_id = args->current_id;
    char *ip = args->ip;
    int port = args->port;
    

    // 1. Create and connect the socket
    args->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (args->socket_fd < 0) {
        printf("Socket creation failed for ip %s\n", ip);
        free(args);
        return NULL;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        printf("Invalid IP for ip %s\n", ip);
        close(args->socket_fd);
        free(args);
        return NULL;
    }

    if (connect(args->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed for ip %s\n", ip);
        close(args->socket_fd);
        free(args);
        return NULL;
    }

    uint8_t type = (uint8_t)INIT;

    secure_send(args->socket_fd, &type, sizeof(type));

    // send the current id
    if (secure_send(args->socket_fd, &current_id, sizeof(current_id)) != sizeof(current_id)) {
        printf("Failed to send current id to ip %s\n", ip);
        close(args->socket_fd);
        free(args);
        return NULL;
    }

    // 2. Exchange public keys
    if (secure_send(args->socket_fd, args->current_pubKey, PUB_SIZE) != PUB_SIZE) {
        printf("Failed to send host pubKey to ip %s\n", ip);
        close(args->socket_fd);
        free(args);
        return NULL;
    }

    if (secure_recv(args->socket_fd, args->peer_pubKey, PUB_SIZE) != PUB_SIZE) {
        printf("Failed to receive guest pubKey from ip %s\n", ip);
        close(args->socket_fd);
        free(args);
        return NULL;
    }

    free(args);
    // 4. Mark node as ready
    printf("-------------------------------------------------------\n");
    printf("The IP %s connected and session key initialized with socket ID%d and peer pubKey %s\n", ip, args->socket_fd, args->peer_pubKey);
    printf("-------------------------------------------------------\n");
    // Do not close the socket — keep it open for future use!
    return NULL;
}



void ocall_peer_init(uint8_t *current_pubKey, uint8_t *peer_pubKey, const char *ip, int port, int *socket_fd, int current_id) {

    ThreadArgs *args = malloc(sizeof(ThreadArgs));
    if (!args) {
        printf("Failed to allocate memory for thread args\n");
        return;
    }

    args->current_pubKey = current_pubKey;
    args->peer_pubKey = peer_pubKey;
    args->ip = ip;
    args->port = port;
    args->socket_fd = socket_fd;
    args->current_id = current_id;

    pthread_t thread;
    if (pthread_create(&thread, NULL, connection_thread_func, args) != 0) {
        printf("Failed to create thread for node %s\n", ip);
        free(args);
        return;
    }


    pthread_detach(thread);  // Let the thread run independently
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

void preprocessing(sgx_enclave_id_t eid, int mode,  char* fileChunkName, FileDataTransfer *fileDataTransfer) {

    init_keys();
    // the stored file name for local peer
    char *current_file = "App/decentralize/chunks/current_file.bin";

    if (mode == 1) {
        // reciever mode

        printf("+++mode 1 started+++\n");
        reciever_data_initialization(current_file);
        printf("+++mode 1 finished+++\n");
    } else if (mode == 2) {
        // performer mode
        printf("+++mode 2 started+++\n");
        if (RAND_bytes((unsigned char*)PC_KEY, 16) != 1) {}
        initiate_Chunks(fileChunkName, current_file);
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
   fileDataTransfer->current_id = Current_Chunk_ID;

//    strcpy(fileChunkName, current_file);
//    fileChunkName = current_file;


    // ------------------------------------------------------------------------------
    //                                 rest of the code for all modes
    pthread_t listener_thread;
    sgx_enclave_id_t *eid_ptr = malloc(sizeof(sgx_enclave_id_t));
    // the reason for this is that the pthread_create only accepts pointer
    *eid_ptr = eid;
    if (pthread_create(&listener_thread, NULL, listener_thread_func, eid_ptr) != 0) {
        perror("Failed to create listener thread");
        free(eid_ptr);
        return 1;
    }
    pthread_detach(listener_thread);


    printf("Preprocessing started\n");
   
   
    // // Generate a random K x N matrix A
    // int A[K][N];
    // for (int i = 0; i < K; i++) {
    //     for (int j = 0; j < N; j++) {


}
