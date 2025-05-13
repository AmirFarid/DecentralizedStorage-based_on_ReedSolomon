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


#include "../rs/rs.h"
#include "../aes/aes.h"
#define NUM_NODES 2
#define N 5
#define K 3
int Number_Of_Blocks;

typedef struct {
    const char* ip;
	uint8_t is_parity_peer;
	uint8_t chunk_id;
    int port;
    int socket_fd;
    int is_ready;
} NodeInfo;

NodeInfo nodes[NUM_NODES] = {
    {"192.168.1.1", 8080, -1, 0}, // This is the host node do not count it as a node
    {"141.219.210.172", 0,0, 8080, -1, 0},
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
    uint8_t *sgx_host_pubKey;
    uint8_t *sgx_guest_pubKey;
    uint8_t nodeID;
} ThreadArgs;

#define CHUNK_PATH_FORMAT "App/decentralize/chunks/data_%d.dat"
#define CHUNK_BUFFER_SIZE 1024

// Parity chunk encryption key
uint32_t PC_KEY[4];
uint32_t PC_KEY_received[4];



// ------------------------------------------------------------------------------
//                                 helper functions
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


void* connection_thread_func(void *args_ptr) {
    ThreadArgs *args = (ThreadArgs *)args_ptr;
    uint8_t nodeID = args->nodeID;

    if (nodeID >= NUM_NODES) {
        printf("Invalid nodeID: %d\n", nodeID);
        free(args);
        return NULL;
    }

    NodeInfo *node = &nodes[nodeID];

    // 1. Create and connect the socket
    node->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (node->socket_fd < 0) {
        printf("Socket creation failed for node %d\n", nodeID);
        free(args);
        return NULL;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(node->port);

    if (inet_pton(AF_INET, node->ip, &server_addr.sin_addr) <= 0) {
        printf("Invalid IP for node %d\n", nodeID);
        close(node->socket_fd);
        free(args);
        return NULL;
    }

    if (connect(node->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed for node %d\n", nodeID);
        close(node->socket_fd);
        free(args);
        return NULL;
    }

    // 2. Exchange public keys
    if (send(node->socket_fd, args->sgx_host_pubKey, KEY_SIZE, 0) != KEY_SIZE) {
        printf("Failed to send host pubKey to node %d\n", nodeID);
        close(node->socket_fd);
        free(args);
        return NULL;
    }

    ssize_t received = recv(node->socket_fd, args->sgx_guest_pubKey, KEY_SIZE, 0);
    if (received != KEY_SIZE) {
        printf("Failed to receive guest pubKey from node %d\n", nodeID);
        close(node->socket_fd);
        free(args);
        return NULL;
    }


    // 4. Mark node as ready
    node->is_ready = 1;
    printf("Node %d connected and session key initialized.\n", nodeID);

    // Do not close the socket — keep it open for future use!
    free(args);
    return NULL;
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


    FILE *fp = fopen(save_path, "wb");
    if (!fp) {
        perror("Failed to open file for writing");
        return NULL;
    }

    uint8_t buffer[1024];
    ssize_t len;

    // receive the file type and size
    secure_recv(client_socket, &file_type, sizeof(file_type));
    secure_recv(client_socket, &file_size, sizeof(file_size));


    // while ((len = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
    // while ((len = secure_recv(client_socket, buffer, file_size)) > 0) {
    for (size_t i = 0; i < file_size/CHUNK_BUFFER_SIZE; i++)
    {
        len = secure_recv(client_socket, buffer, CHUNK_BUFFER_SIZE);
        printf("this is the %d th len: %d\n", i, len);
        fwrite(buffer, 1, len, fp);

    }


    if (file_type == 2) {
        secure_recv(client_socket, PC_KEY_received, 16);
    }


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
        return -1; // failure
    }
}

// ------------------------------------------------------------------------------
//                                 client functions


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



void handle_client(sgx_enclave_id_t eid, int client_socket) {

    // Server side
    
    // uint8_t sgx_host_pubKey[KEY_SIZE];
    // uint8_t sgx_guest_pubKey[KEY_SIZE];
    // uint8_t nonce[KEY_SIZE];

    // ssize_t ns = recv(client_socket, nonce, KEY_SIZE, 0);


    // // Get the host pubKey and generate private key save in sgx2sgx_privKey
    // ecall_get_pubKey(eid, sgx_host_pubKey);

    // // Do key exchange first...
    // ssize_t received = recv(client_socket, sgx_guest_pubKey, KEY_SIZE, 0);
    // if (received != KEY_SIZE) {
    //     printf("Failed to receive host pubKey from client\n");
    

    // send(client_socket, sgx_host_pubKey, KEY_SIZE, 0);

    printf("Client connected\n");

    while (1) {
        uint8_t buffer[1024];
        ssize_t len = recv(client_socket, buffer, sizeof(buffer), 0);
        if (len <= 0) break; // client disconnected

        if (strncmp((char*)buffer, "BLOCK:", 6) == 0) {
            int blockNumber;
            if (sscanf((char*)buffer + 6, "%d", &blockNumber) == 1) {
                printf("Block request received: %d\n", blockNumber);
                // process block request here
            } else {
                printf("Failed to parse block number\n");
            }

        } else if (strncmp((char*)buffer, "Close:", 6) == 0) {
            printf("Client disconnected\n");
            break;
        } else {
            // unknown command
        }
    }

    close(client_socket);
}





// ------------------------------------------------------------------------------
//                                 server functions

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

        
            Number_Of_Blocks = get_file_size(fp)/BLOCK_SIZE;
            rename_file(path, current_file);
            printf("Number of blocks: %d\n", Number_Of_Blocks);

            //TODO: set the is_parity_peer to 0 for the first node ( idea save the current node ip and compare)
            nodes[i].is_parity_peer = 0;

            continue;
        } 


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
        secure_send(sock, &chunk_type, sizeof(chunk_type));
        secure_send(sock, &chunk_len, sizeof(chunk_len));
        // secure_send(sock, chunk, chunk_len);     

        // 4. Send file in chunks
        uint8_t buffer[CHUNK_BUFFER_SIZE];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {

            if (i > K) { // encrypt the parity chunks
                EncryptData(PC_KEY, buffer, bytes_read);
            }
            ssize_t sent = secure_send(sock, buffer, bytes_read);
            // send(sock, buffer, bytes_read, 0);
            if (sent < 0) {
                perror("Send failed");
                break;
            }
        }

        // TODO: send the chunk id to the enclave and set the key through ecall_peer_init
        // 6. for parity chunks, send key
        if (chunk_type == 2) {
            secure_send(sock, PC_KEY, 16);
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



void ocall_sgx2sgx_connection(uint8_t *sgx_host_pubKey, uint8_t *sgx_guest_pubKey, uint8_t nodeID) {
    ThreadArgs *args = malloc(sizeof(ThreadArgs));
    if (!args) {
        printf("Failed to allocate memory for thread args\n");
        return;
    }

    args->sgx_host_pubKey = sgx_host_pubKey;
    args->sgx_guest_pubKey = sgx_guest_pubKey;
    args->nodeID = nodeID;

    pthread_t thread;
    if (pthread_create(&thread, NULL, connection_thread_func, args) != 0) {
        printf("Failed to create thread for node %d\n", nodeID);
        free(args);
        return;
    }

    pthread_detach(thread);  // Let the thread run independently
}


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

// ------------------------------------------------------------------------------




// ------------------------------------------------------------------------------
//                                 main functions

void preprocessing(sgx_enclave_id_t eid, int mode,  char* fileChunkName, int *numBlocks) {

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
   
   *numBlocks = Number_Of_Blocks;

    // ------------------------------------------------------------------------------
    //                                 rest of the code for all modes
    pthread_t listener_thread;
    sgx_enclave_id_t *eid_ptr = malloc(sizeof(sgx_enclave_id_t));
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
