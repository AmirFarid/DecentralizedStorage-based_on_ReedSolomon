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
    send_data_to_server("send_parity", strlen("send_parity"));
	send_data_to_server(&size, sizeof(size_t));
	send_data_to_server(&startPage, sizeof(int));
    send_data_to_server(parityData, sizeof(uint8_t) * size);
    usleep(10000000);

}

void ocall_init_parity(int numBits) 
{
	send_data_to_server("state_2", strlen("state_2"));
	send_data_to_server(&numBits, sizeof(int)); // TODO: write response on server side in VM.
}

void ocall_write_partition(int numBits)
{
    send_data_to_server("write_partition", strlen("write_partition"));
    send_data_to_server(&numBits, sizeof(int));
}

void ocall_write_page(int pageNum, uint8_t *pageData) 
{
    send_data_to_server("write_page", strlen("write_page"));
    send_data_to_server(&pageNum, sizeof(int));
    send_data_to_server(pageData, sizeof(uint8_t) * PAGE_SIZE);
}

void ocall_end_genPar() 
{
	send_data_to_server("end_genPar", strlen("end_genPar"));
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
	send_data_to_server("get_nonce", strlen("get_nonce")); // TODO: Change this on server side to nonce.

	/* Send nonce to server */
	send_data_to_server(nonce, sizeof(uint8_t) * KEY_SIZE);
}

void ocall_get_segment(const char *fileName, int segNum, uint8_t *segData, int type) //TODO: make it clear when pages vs segments need to be read.
{

    /* Call server function get_segment */
    send_data_to_server("get_segment", strlen("get_segment"));

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
    printf("ocall_ftl_init took %f microseconds to complete.\n", total_time);

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
    if (!buffer) {
        printf("Error: NULL pointer passed to ocall_printint\n");
        return;
    }

	printf("%d\n",*buffer);

}

void ocall_printdouble(double *buffer) 
{

	printf("%f\n",*buffer);

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

    struct timespec start, end;

    // start time
    clock_gettime(CLOCK_MONOTONIC, &start);

    
	//printf("call ecall\n");
	int fileNum = 0;
    status = ecall_file_init(eid, &fileNum, tag, *sigma, fileDataTransfer, numBlocks, sizeof(FileDataTransfer)); // make sure the change to returning fileNum works properly.
    
        // end time
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double s_time = start.tv_sec + (start.tv_nsec / 1e9);
    double e_time = end.tv_sec + (end.tv_nsec / 1e9);

    printf("Preprocessing time: %f seconds\n", e_time - s_time);
    
    
    
    
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
    // free(fileDataTransfer);

    printf("--------------Test 10------------\n");
    // free(fileDataTransfer);
	/* server function file_init has now completed execution, it does not require any more data */
	printf("generate parity!\n");
    free(tag);
    free(sigma);
    free(sigma_mem);

    // our logics are the same ----
    
   // ecall_generate_file_parity(eid, fileNum); // Note: The convention for this call is slightly different than the rest of the file initialization.
                                         // Above, the gennerated data is directly retrurned, rather than written via an ocall, as is done here.
}


#include <openssl/rand.h>
#include <openssl/err.h>
#include "jerasure/reed_sol.h"
#include <time.h>

void ocall_test_time(double *time) {

    struct timespec currentTime;

    clock_gettime(CLOCK_MONOTONIC, &currentTime);

    // printf("time: %f\n", currentTime.tv_sec + (currentTime.tv_nsec / 1e9));

    *time = (currentTime.tv_sec + (currentTime.tv_nsec / 1e9));

}


#define LOG_FILE "logfile%d-%d.txt"
void ocall_log_double(const char *format, double value) {
    log_double(format, value);
}

int inN;
int inK;


void log_double(const char *format, double value) {
    char log_file[100];
    snprintf(log_file, sizeof(log_file), LOG_FILE, inN, inK);

    FILE *log_fp = fopen(log_file, "a");
    if (log_fp == NULL) {
        perror("Failed to open log file");
        return;
    }

    // Add timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    
    if (strcmp(format, "=") == 0) {
        fprintf(log_fp, "===============================================\n");
    }else{
        fprintf(log_fp, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
        fprintf(log_fp, format, value);
        fprintf(log_fp, "\n");
    }

    // Log the formatted string with the double value

    fclose(log_fp);
}

void ocall_get_counter(int *value) {
    *value = get_counter();
}

void beep(){
    printf("\a"); fflush(stdout); usleep(100000); // beep
    printf("\a"); fflush(stdout); usleep(100000); // beep
    printf("\a"); fflush(stdout); usleep(400000); // beep
    printf("\a"); fflush(stdout); usleep(200000);
    printf("\a"); fflush(stdout); usleep(200000);
    printf("\a"); fflush(stdout); usleep(600000); // long pause

    // One more for comedy punch
    printf("\a"); fflush(stdout);
}

int main(void) 
{


    struct timespec start, end;
    struct timeval start_time, end_time;
    double cpu_time_used;

    int n = 12;
    int k = 4;
    int m = n - k;
    int mode = 1;

    inN = n;
    inK = k;
    
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int update = 0;

    // Initialize the Intel SGX runtime
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, &update, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Error creating enclave: %d\n", ret);
        return 1;
    }


    char fileName[512];
    strcpy(fileName, "/home/amoghad1/f/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/testfile");
    // strncpy(fileName, "/home/amoghad1/f/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/random_160KB_40.bin", sizeof(fileName) - 1);
    fileName[sizeof(fileName) - 1] = '\0';


    FileDataTransfer *fileDataTransfer =  malloc(sizeof(FileDataTransfer));


    // ------------------------------------ Pre processing ------------------------------------
    // start time
    
    printf("==== PREPROCESSING ====\n");
    // clock_gettime(CLOCK_MONOTONIC, &start);

    preprocessing(eid, mode, fileName, fileDataTransfer , n, k);
    
    // ------------------------------------ load file data ------------------------------------
    // load all the parities from files to does not make any overhead.
    load_file_data(fileName, fileDataTransfer->numBlocks, mode, k, n, eid);

    // getchar();

    // ------------------------------------  initialization ------------------------------------
    
    strcpy(fileName, fileDataTransfer->fileName);

    printf("fileName: %s\n", fileName);
    printf("fileDataTransfer->fileName: %s\n", fileDataTransfer->fileName);
    printf("fileDataTransfer->nodes[0].ip: %s\n", fileDataTransfer->nodes[0].ip);
    printf("fileDataTransfer->nodes[0].port: %d\n", fileDataTransfer->nodes[0].port);
    printf("fileDataTransfer->nodes[0].chunk_id: %d\n", fileDataTransfer->nodes[0].chunk_id);


    printf("==== FTL INIT ====\n");

    int ftl_sleeps = get_counter();
    log_double("++++++++++++++++++++++++++++++++++++++", 0.1 );
    
    ret = ecall_init(eid, fileDataTransfer, sizeof(FileDataTransfer));
    
    



    printf("Press enter to continue for File INIT\n");
    getchar();


    if (ret != SGX_SUCCESS) {
        printf("Error calling enclave function: %d\n", ret);
        return 1;
    }


    int ftl_sleeps3 = get_counter();
    log_double("++++++++++++++++++++++++++++++++++++++", 0.1 );


    clock_gettime(CLOCK_MONOTONIC, &start);

    printf("==== FILE INIT ====\n");
    app_file_init(eid, fileDataTransfer);

    //------------------------------------------------------------------------------------------------------INITIALIZATION FINISHED
    // end time
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double s_time = start.tv_sec + (start.tv_nsec / 1e9);
    double e_time = end.tv_sec + (end.tv_nsec / 1e9);
    printf("wait here\n");
    getchar();
    getchar();
    getchar();
    getchar();
    ecall_retrieve_File(eid, fileName);





    ecall_small_corruption(eid, fileName, 1);


    log_double("=",0);
    log_double("FILE INIT TOTAL time: %f seconds", e_time - s_time);
    log_double("=",0);


    log_double("FTL SLEEPS: - %f", (double)ftl_sleeps3 * 0.1 );
    log_double("++++++++++++++++++++++++++++++++++++++", 0.1 );


    printf("Press enter to continue for retrieve plain file\n");
    getchar();


    ecall_retrieve_plain_File(eid, fileName);


    // ecall_small_corruption(eid, fileName, 0);
    log_double("++++++++++++++++++++++++++++++++++++++", 0.1 );
    
    log_double("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", 0.1 );
    int tcp_sleeps = get_dcounter();
    ecall_retrieve_File(eid, fileName);
    tcp_sleeps = get_dcounter() - tcp_sleeps;
    log_double("total SLEEPS: - %f",  (double)tcp_sleeps * 30 );
    log_double("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", 0.1 );
    printf("Stop here\n");
    getchar();
    getchar();
    getchar();
    getchar();
    getchar();    
    getchar();
    printf("Press enter to continue for retrieve file\n");


    
    struct timespec start1, end1;

    clock_gettime(CLOCK_MONOTONIC, &start1);
    
    

    clock_gettime(CLOCK_MONOTONIC, &end1);

    double s_time1 = start1.tv_sec + (start1.tv_nsec / 1e9);
    double e_time1 = end1.tv_sec + (end1.tv_nsec / 1e9);

    log_double("=",0);
    log_double("RETRIEVE FILE time: %f seconds", e_time1 - s_time1);
    log_double("=",0);
    
    
    
    // log_double("FTL SLEEPS end: - %f", (double)ftl_sleeps2_p);
    // log_double("TCP SLEEPS: - %f", (double)tcp_sleeps);

    printf("Press enter to continue for small corruption Block 0 and audit file\n");
    getchar();

    log_double("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$", 0.1 );

    ecall_small_corruption(eid, fileName, 0);


    int status = 1;
    printf("==== AUDIT FILE ====\n");
    ecall_audit_file(eid, fileName, &status);




    log_double("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$", 0.1 );

    beep();

    printf("Press enter to continue for small corruption Block 1\n");
    getchar();

    ecall_small_corruption(eid, fileName, 1);


    // ============================================================ Normal flow ============================================================


    printf("Press enter to continue for small corruption Block 0\n");
    getchar();

    // ------------------------------------ small corruption BLOCK 0 ------------------------------------
    printf("==== SMALL CORRUPTION ====\n");
    printf("==== Block 0 ====\n");


    printf("==== Block 0 ====\n");

    ecall_small_corruption(eid, fileName, 0);


    printf("Press enter to continue for small corruption Block 1\n");
    getchar();


    // ------------------------------------ small corruption BLOCK 1 ------------------------------------
    printf("==== SMALL CORRUPTION ====\n");
    printf("==== Block 1 ====\n");

    ecall_small_corruption(eid, fileName, 1);


    printf("Press enter to continue for audit file\n");
    getchar();
    
    // ------------------------------------ audit file ------------------------------------
    // int status = 1;
    printf("==== AUDIT FILE ====\n");
    
    ecall_audit_file(eid, fileName, &status);

    
    
    printf("Press enter to continue for retrieve file\n");
    getchar();
    
    // ------------------------------------ retrieve file ------------------------------------

    ecall_retrieve_File(eid, fileName);


    if(status == 0) {
        printf("SUCCESS!!!\n");
    }

    // Destroy the enclave
    ret = sgx_destroy_enclave(eid);
    if (ret != SGX_SUCCESS) {
        printf("Error destroying enclave: %d\n", ret);
        return 1;
    }

    free(fileDataTransfer);

    beep();

    return 0;
}
