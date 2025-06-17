/*
 * Application side function for interaction between the trusted application running in an Enclave,
 * and the server which interacts directly with the storage device.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include "sgx_urts.h"
#include "sharedTypes.h"
#include "Enclave_u.h"
#include "ccom.h"
#include <time.h>


#include "decentralize/decentralize.h"
#include "prp/prp.h"

#include <string.h>

void ocall_send_parity(int startPage, uint8_t *parityData, size_t size)
{
    send_data_to_server("send_parity", 12);
	send_data_to_server(&size, sizeof(size_t));
	send_data_to_server(&startPage, sizeof(int));
    send_data_to_server(parityData, sizeof(uint8_t) * size);
    usleep(10000000);

}

void ocall_init_parity(int numBits) 
{
	send_data_to_server("state_2", 8);
	send_data_to_server(&numBits, sizeof(int)); // TODO: write response on server side in VM.
}

void ocall_write_partition(int numBits)
{
    send_data_to_server("write_partition", 16);
    send_data_to_server(&numBits, sizeof(int));
}

void ocall_write_page(int pageNum, uint8_t *pageData) 
{
    send_data_to_server("write_page", 11);
    send_data_to_server(&pageNum, sizeof(int));
    send_data_to_server(pageData, sizeof(uint8_t) * PAGE_SIZE);
}

void ocall_end_genPar() 
{
	send_data_to_server("end_genPar", 11);
}



/*
 * Sends the public challenge number to the server, which passes it to the storage device.
 * Simply establish a connection and send the number.
 *
 * No returns
 */
void ocall_send_nonce(uint8_t *nonce) 
{


	/* Call server function get_nonce*/
	send_data_to_server("get_nonce", 12); // TODO: Change this on server side to nonce.

	/* Send nonce to server */
	send_data_to_server(nonce, sizeof(uint8_t) * KEY_SIZE);
}

void ocall_get_segment(const char *fileName, int segNum, uint8_t *segData, int type) //TODO: make it clear when pages vs segments need to be read.
{

    /* Call server function get_segment */
    send_data_to_server("get_segment", 11);

    /* Send fileName to server*/
    send_data_to_server(fileName, strlen(fileName));

    /* Send segNum to server*/
    send_data_to_server(&segNum, sizeof(int));

    send_data_to_server(&type, sizeof(int));

    /* Recieve segData from server */
    uint8_t *temp;
    temp = (uint8_t *) receive_data_from_server(SEGMENT_SIZE);

    if (temp != NULL) {
        memcpy(segData, temp, SEGMENT_SIZE);
        free(temp);
    } else {
        // handle error
    }

    //printf("segment data: ");
}

/*
 * Gets the data from the referenced block, in the specified file.
 *
 * Implicit return : Populate uint8_t data with the data from the requested block in the specified file.
 */
void ocall_get_block(uint8_t *data, size_t segSize, int segPerBlock, int blockNum, char *fileName) 
{

    // Open the necessary file for reading
    int fd = open(fileName, O_RDONLY);
    if (fd < 0) {
        printf("Error: cannot open file %s\n", fileName);
        exit(1);
    }

    // Go to block offset
    off_t offset = blockNum * (off_t) segSize * segPerBlock;
    if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
        printf("Error: cannot seek to offset %lld in file %s\n", (long long) offset, fileName);
        close(fd);
        exit(1);
    }

    // Read data into buffer
    uint8_t buffer[segSize * segPerBlock];
    ssize_t bytesRead = read(fd, buffer, segSize * segPerBlock);
    if (bytesRead < 0) {
        printf("Error: cannot read file %s\n", fileName);
        close(fd);
        exit(1);
    }
    close(fd);

    // Copy buffer into data arr

    memcpy(data, buffer, segSize * segPerBlock);

}


/*
 * Send the sgx public ecc key to the storage device at address 951388. 
 * The storage device will use this for generating the shared ecc Diffie-Hellman key
 * and write its public ecc key to address 951388 (in reserved area).
 * We can then read from this location to pass the storage device public key into SGX,
 * which can be used to generate the shared Diffie-Hellman key in SGX.
 *
 * Implicit return : Populates ftl_pubkey with the storage device public ecc key.
 */
void ocall_ftl_init(uint8_t *sgx_pubKey, uint8_t *ftl_pubKey) 
{

    int client_fd;
    struct timeval start_time, end_time;
    double total_time;

    /* Call server function ftl_init */
    client_fd = create_client_socket();
    connect_to_server(client_fd);
    write(client_fd, "ftl_init", 8); /* Specify which function to call in server */
    close(client_fd);

    /* Provide input to ftl_init */
    client_fd = create_client_socket();
    connect_to_server(client_fd);
	
    write(client_fd, sgx_pubKey, 64); /* Send SGX public key to server */
    close(client_fd);



    /* Recieve the output of ftl_init */
    client_fd = create_client_socket();
    connect_to_server(client_fd); /* Once server finishes processing, read storage device public key */
    read(client_fd, ftl_pubKey, 64);
    close(client_fd);

    gettimeofday(&end_time, NULL);
    total_time = (double)(end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_usec - start_time.tv_usec);

    /* Print the time taken by the function */
    //printf("ocall_ftl_init took %f microseconds to complete.\n", total_time);

    /* We now have storage device public key */
}

/* Used for debugging purposes, to print a value within the enclave */
void ocall_printf(unsigned char *buffer, size_t size, int type) 
{
	if(type == 1) {
		for(int i = 0; i < (int)size; i++) {
			printf("%X", buffer[i]);
		}
		printf("\n");
	}
	else if(type == 2) {
		for(int i = 0; i < (int)size; i++) {
			printf("%d",buffer[i]);
		}
		printf("\n");
	}
	else if (type == 0) {
		for(int i = 0; i < (int)size; i++) {
			printf("%c", buffer[i]);
		}
		printf("\n");
	}
	

}

void ocall_printint(int *buffer) 
{

	printf("%d\n",*buffer);

	

}



/*  
 * Perform the initialization steps for a file. Generates all data necessary to perform file integrity auditing.
 *
 * Implicit returns : Writes the file and POR data to the storage device. Calls ecall_file_init,
 * Which initializes many values in the enclave.
 */
void app_file_init(sgx_enclave_id_t eid, FileDataTransfer *fileDataTransfer) 
{



    char fileName[512];
    int numBlocks;
    sgx_status_t status;

	/* Check input values */
    if (fileDataTransfer->fileName == NULL) {
        printf("Error: filename is NULL\n");
        return;
    }else{
        strncpy(fileName, fileDataTransfer->fileName, 512);
        printf("fileName in app file init: %s\n", fileName);
    }

    if (fileDataTransfer->numBlocks <= 0) {
        printf("Error: numBlocks must be positive\n");
        return;
    }else{
        numBlocks = fileDataTransfer->numBlocks;
        printf("numBlocks in app file init: %d\n", numBlocks);
    }


	Tag *tag = malloc(sizeof(Tag));
	// Allocate memory for sigma
	uint8_t **sigma = malloc(numBlocks * sizeof(uint8_t *));
    if (!sigma) {
    fprintf(stderr, "sigma allocation failed\n");
    exit(1);
    }
    printf("numBlocks = %d\n", numBlocks);
printf("PRIME_LENGTH = %d\n", PRIME_LENGTH);
printf("sigma_mem size = %zu\n", numBlocks * (PRIME_LENGTH / 8) * sizeof(uint8_t));

    uint8_t *sigma_mem = malloc(numBlocks * (PRIME_LENGTH / 8) * sizeof(uint8_t));
    if (!sigma_mem) {
    fprintf(stderr, "sigma_mem allocation failed\n");
    exit(1);
    }
	
    for (int i = 0; i < numBlocks; i++) {
    	sigma[i] = sigma_mem + i * (PRIME_LENGTH / 8);
    	memset(sigma[i], 0, (PRIME_LENGTH / 8) * sizeof(uint8_t)); /* Initialize all sigma to 0 */
        printf("sigma[%d] = %p\n", i, sigma[i]);

	}
    
    /* Call ecall_file_init to initialize tag and sigma */

    FILE *file = fopen(fileName, "rb");
    // uint8_t blockData[BLOCK_SIZE];


	//printf("call ecall\n");
	int fileNum = 0;
    status = ecall_file_init(eid, &fileNum, tag, *sigma, fileDataTransfer, numBlocks, sizeof(FileDataTransfer)); // make sure the change to returning fileNum works properly.
    if (status != SGX_SUCCESS) {
        printf("Error calling enclave function: %d\n", status);
        return;
    }

    printf("------------info 3--------------\n");
    printf("Sending to enclave:\n");
    printf("  fileName: %s\n", fileDataTransfer->fileName);
    printf("  numBlocks: %d\n", fileDataTransfer->numBlocks);
    printf("  nodes[0].ip: %s\n", fileDataTransfer->nodes[0].ip);
    printf("  n = %d, k = %d, current_id = %d\n",fileDataTransfer->n, fileDataTransfer->k, fileDataTransfer->current_id);
    printf("--------------------------\n");

    
    
	int client_fd;
    uint8_t *blockData = malloc(BLOCK_SIZE);
    if (!blockData) { perror("malloc blockData"); return; }

	/* Call file initialization function on server */
	client_fd = create_client_socket();
    connect_to_server(client_fd);
	write(client_fd, "file_init", 9);
	close(client_fd);
    /* Send file name and number of blocks to server function file_init */
	client_fd = create_client_socket();
	connect_to_server(client_fd);
    write(client_fd, fileDataTransfer->fileName, strlen(fileDataTransfer->fileName)); /* Send file Name */
	close(client_fd);

	client_fd = create_client_socket();
	connect_to_server(client_fd);
    write(client_fd, &fileDataTransfer->numBlocks, sizeof(fileDataTransfer->numBlocks)); /* Send number of blocks */
	close(client_fd);


    printf("--------------Test 5------------\n");
         /* Send each block data to the server */
    for (int i = 0; i < fileDataTransfer->numBlocks; i++) {
        printf("--------------Test 6------------\n");

        /* Read the i-th block from the file into blockData */
        if (fread(blockData, BLOCK_SIZE, 1, file) != 1) {
            fprintf(stderr, "Error: failed to read block %d from file %s\n", i, fileDataTransfer->fileName);
            fclose(file);
            close(client_fd);
            return;
        }
    printf("--------------Test 7------------\n");
        
        /* Send the i-th block to the server */
		client_fd = create_client_socket();
		connect_to_server(client_fd);

		int bytes_sent = 0;
		int bytes_left = BLOCK_SIZE;
		while (bytes_left > 0) {
    		int bytes_written = write(client_fd, blockData + bytes_sent, bytes_left);
    		if (bytes_written < 0) {
        		perror("Error sending data");
        		close(client_fd);
        		exit(1);
    		}
    		bytes_sent += bytes_written;
    		bytes_left -= bytes_written;
		}
		close(client_fd);
	//	printf("Sent block %d\n", i);
    }
	    /* All blocks sent to server */

   
    printf("--------------Test 8------------\n");

    /* Send each sigma to the server */
    for (int i = 0; i < fileDataTransfer->numBlocks; i++) {
        /* Send the i-th sigma to the server */
		client_fd = create_client_socket();
		connect_to_server(client_fd);
        write(client_fd, sigma[i], PRIME_LENGTH / 8);
		close(client_fd);
    }
	/* All sigma sent to server */
    /* Send the tag to the server */
	client_fd = create_client_socket();
	connect_to_server(client_fd);
    write(client_fd, tag, sizeof(Tag));
	close(client_fd);

    if (!file) {
    perror("fopen failed");
    printf("fopen failed\n");
    return;
    }
    fclose(file);
    free(blockData);
    free(fileDataTransfer);

    printf("--------------Test 10------------\n");
    // free(fileDataTransfer);
	/* server function file_init has now completed execution, it does not require any more data */
	printf("generate parity!\n");

    // our logics are the same ----
    
   // ecall_generate_file_parity(eid, fileNum); // Note: The convention for this call is slightly different than the rest of the file initialization.
                                         // Above, the gennerated data is directly retrurned, rather than written via an ocall, as is done here.
}


#include <openssl/rand.h>
#include <openssl/err.h>
#include "jerasure/reed_sol.h"
#include <time.h>

int main(void) 
{

    sgx_enclave_id_t eid;
    sgx_status_t ret;

    // Initialize the Intel SGX runtime
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: %d\n", ret);
        return 1;
    }

// ---------------------------------------------------------------------------------

   
    // int *matrix_test_2 = malloc(sizeof(int) * 3 * 3);

    // matrix_test_2 = reed_sol_vandermonde_coding_matrix(3, 3, 16);

    // printf("================ matrix_test_2 ================\n");
    // jerasure_print_matrix(matrix_test_2, 3, 3, 16);
    // printf("matrix_test_2[0]: %d\n", matrix_test_2[0]);
    // printf("matrix_test_2[1]: %d\n", matrix_test_2[1]);
    // printf("matrix_test_2[2]: %d\n", matrix_test_2[2]);
    // printf("matrix_test_2[3]: %d\n", matrix_test_2[3]);
    // printf("matrix_test_2[4]: %d\n", matrix_test_2[4]);
    // printf("matrix_test_2[5]: %d\n", matrix_test_2[5]);
    // printf("matrix_test_2[6]: %d\n", matrix_test_2[6]);
    // printf("matrix_test_2[7]: %d\n", matrix_test_2[7]);
    // printf("matrix_test_2[8]: %d\n", matrix_test_2[8]);
    // printf("================================================\n");ma

    // getchar();


    struct timeval start_time, end_time;
    double cpu_time_used;
    int waittime;

// ---------------------------------------------------------------------------------



    char fileName[512];
    strcpy(fileName, "/home/amoghad1/f/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/testFile");


    // Amir M M Farid

    NodeInfo nodes[NUM_NODES];

    int n = 6;
    int k = 3;
    int mode = 2;

    FileDataTransfer *fileDataTransfer =  malloc(sizeof(FileDataTransfer));
    // ------------------------------------ Pre processing ------------------------------------
    // clock_t start0 = clock();
    gettimeofday(&start_time, NULL);
    preprocessing(eid, mode, fileName, fileDataTransfer , n, k);
    // clock_t end0 = clock();
    gettimeofday(&end_time, NULL);
    waittime = 3;
    cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");

    // printf("Time: %f preprocessing\n", ((double)(end0 - start0)) / CLOCKS_PER_SEC);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");

    getchar();

    if (mode == 2) {
        load_file_data(fileName, fileDataTransfer->numBlocks);
    }

    // printf("press enter to continue\n");
    // getchar();
    

    strcpy(fileName, fileDataTransfer->fileName);

    // for (int i = 0; i < NUM_NODES; i++) {
    //     printf("Node %d: %s:%d\n", i, fileDataTransfer->nodes[i].ip, fileDataTransfer->nodes[i].port);
    // }
    // printf("------------info--------------\n");
    // printf("Sending to enclave:\n");
    // printf("  fileName: %s\n", fileDataTransfer->fileName);
    // printf("  numBlocks: %d\n", fileDataTransfer->numBlocks);
    // printf("  nodes[0].ip: %s\n", fileDataTransfer->nodes[0].ip);
    // printf("  n = %d, k = %d, current_id = %d\n",fileDataTransfer->n, fileDataTransfer->k, fileDataTransfer->current_id);
    // printf("--------------------------\n");


    // printf("File data transfer size: %d\n", sizeof(FileDataTransfer));



    printf("Press enter to continue for initialization\n");
    getchar();

    // Call Enclave initialization function.
    //int result;

    // ------------------------------------  initialization ------------------------------------
    //gettimeofday(&start_time, NULL);
    printf("Call FTL init\n");
    //clock_t start12 = clock();
    gettimeofday(&start_time, NULL);
    ret = ecall_init(eid, fileDataTransfer, sizeof(FileDataTransfer));
    



	//gettimeofday(&end_time, NULL);
    //waittime = 3;
    //cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    //printf("INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);

    if (ret != SGX_SUCCESS) {
        printf("Error calling enclave function: %d\n", ret);
        return 1;
    }

    // Data for initialization provided by local file at the filePath of fileName

    // strcpy(fileName, "/home/jdafoe/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/testFile");
    // printf("------------info 2--------------\n");
    // printf("Sending to enclave:\n");
    // printf("  fileName: %s\n", fileDataTransfer->fileName);
    // printf("  numBlocks: %d\n", fileDataTransfer->numBlocks);
    // printf("  nodes[0].ip: %s\n", fileDataTransfer->nodes[0].ip);
    // printf("  n = %d, k = %d, current_id = %d\n",fileDataTransfer->n, fileDataTransfer->k, fileDataTransfer->current_id);
    // printf("--------------------------\n");
    // Perform file initialization in SGX
    //gettimeofday(&start_time, NULL);
    printf("Call file init\n");
    // it is called in untrusted side
    app_file_init(eid, fileDataTransfer);
    // clock_t end12 = clock();

    gettimeofday(&end_time, NULL);
    waittime = 3;
    cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");
    // printf("Time: %f file init\n", ((double)(end12 - start12)) / CLOCKS_PER_SEC);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");
    //gettimeofday(&end_time, NULL);
    //waittime = 24;
    //cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    
    // printf("Press enter to continue <enter>\n");

    int status = 1;

    gettimeofday(&start_time, NULL);

    ecall_audit_file(eid, fileName, &status);

    gettimeofday(&end_time, NULL);
    waittime = 3;
    cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");
    // printf("Time: %f file init\n", ((double)(end12 - start12)) / CLOCKS_PER_SEC);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");

    // ------------------------------------ this is for testing ------------------------------------
    printf("Press enter to continue for small corruption\n");
    getchar();
    // ecall_compare(eid);ma

    // the block number is 0 for the first block if you are on mode 
    printf("==== SMALL CORRUPTION ====\n");
    printf("==== Block 0 ====\n");

    // ------------------------------------ small corruption ------------------------------------
    // ecall_test_rs(eid, data_test, k_test, n_test, erasures_test);
    // clock_t start2 = clock();
    gettimeofday(&start_time, NULL);
    ecall_small_corruption(eid, fileName, 0);
    // clock_t end2 = clock();

    gettimeofday(&end_time, NULL);
    waittime = 3;
    cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");
    // printf("Time: %f small corruption (without corruption)\n", ((double)(end2 - start2)) / CLOCKS_PER_SEC);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");

    // ecall_test_rs(eid, data_test, k_test, n_test, erasures_test);

    // printf("CRTL C\n");

    printf("==== Block 1 ====\n");
    // clock_t start3 = clock();
    gettimeofday(&start_time, NULL);
    ecall_small_corruption(eid, fileName, 2);
    // clock_t end3 = clock();
    gettimeofday(&end_time, NULL);
    waittime = 3;
    cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");
    // mprintf("Time: %f small corruption (without corruption)\n", ((double)(end3 - start3)) / CLOCKS_PER_SEC);
    printf("()()()()()()()()()()()()()()(()()()()()()())\n");
    
    
    
    
    printf("Press enter to continue for retrieve file\n");
    getchar();

    ecall_retrieve_File(eid, fileName);

    printf("Press enter to continue <enter>\n");

    getchar();

    //printf("FILE INIT TIME: %f with %d wait time\n", cpu_time_used, waittime);

    printf("Call audit file\n");
    //gettimeofday(&start_time, NULL);
    //gettimeofday(&end_time, NULL);
    //waittime = 46;
    //cpu_time_used = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    //printf("AUDIT TIME: %f with %d wait Time\n", cpu_time_used, waittime);

    printf("Press enter to continue <enter>\n");

    getchar();

    // printf("Call decode partition\n");
    // ecall_decode_partition(eid, fileName, 3);

    if(status == 0) {
        printf("SUCCESS!!!\n");
    }

    // Destroy the enclave
    ret = sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS) {
        printf("Error destroying enclave: %d\n", ret);
        return 1;
    }

    return 0;
}
