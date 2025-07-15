/*
 *
 *
 *
 *
 */

#define _GNU_SOURCE
#define PATH "/dev/sdb"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

#include "scom.h"
#include "defs.h"
#include <time.h>

void ftl_initial(uint8_t *sgx_pubKey, uint8_t *ftl_pubKey) 
{

 int fd; 
 if((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Write SGX public key to device
 off_t offset = 951388 * 512;
 void *buf;
 if(posix_memalign(&buf, 512, 64) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 //printf("start KS\n");
 struct timeval start_time, end_time;
 gettimeofday(&start_time, NULL);
 memcpy(buf, sgx_pubKey, 64);
 if (pwrite(fd, buf, 512, offset) == -1) {
 perror("[pwrite]");
 free(buf);
 close(fd);
 return 1;
 }

 fdatasync(fd);
 //printf("end KS\n");

 gettimeofday(&end_time, NULL);
 long int elapsed_time_KS_sec = end_time.tv_sec - start_time.tv_sec;
 long int elapsed_time_KS_micro = end_time.tv_usec - start_time.tv_usec;
 if (elapsed_time_KS_micro < 0) {
 elapsed_time_KS_micro += 1000000;
 elapsed_time_KS_sec--;
 }
 printf("Elapsed FTL INITtime: %ld.%06ld seconds\n", elapsed_time_KS_sec, elapsed_time_KS_micro);


 // Read FTL public key from device
 if(lseek(fd, offset, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }

 if(read(fd, buf, 512) == -1) {
 perror("[read]");
 close(fd);
 return;
 }

 memcpy(ftl_pubKey, buf, 64);

 close(fd);
 return;
}

void get_challnum(int server_fd) 
{

 int client_fd;
 uint8_t challnum[KEY_SIZE];

 client_fd = accept_connection(server_fd);
 read(client_fd, challnum, KEY_SIZE);
 close(client_fd);
 // for(int i = 0; i < KEY_SIZE; i++) {
 // printf("%X", challnum[i]);
 // }
 // printf("\n");

 int fd; 
 if((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Write challenge number to device
 off_t offset = 951392 * 512;
 void *buf;
 if(posix_memalign(&buf, 512, KEY_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 struct timeval start, end;
 gettimeofday(&start, NULL);
 memcpy(buf, challnum, KEY_SIZE);
 if (pwrite(fd, buf, 512, offset) == -1) { 
 perror("[pwrite]");
 free(buf);
 close(fd);
 return -1;
 }

 fsync(fd);

 gettimeofday(&end, NULL);
 long seconds = end.tv_sec - start.tv_sec;
 long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

 printf("Time elapsed Give challNum: %ld.%06ld seconds\n", seconds, micros);

}

void get_segment(int server_fd) 
{

 int client_fd;
 uint8_t segData[SEGMENT_SIZE];
 uint8_t buffer[BUFFER_SIZE];

 /* Recieve fileName */
 client_fd = accept_connection(server_fd);
 int fileNameLen = read(client_fd, buffer, FILE_NAME_LEN);
 close(client_fd);

 char fileName[fileNameLen+1];
 strncpy(fileName, buffer, fileNameLen);
 fileName[fileNameLen] = '\0';

 /* Recieve segNum */
 int segNum;
 client_fd = accept_connection(server_fd);
 read(client_fd, &segNum, sizeof(int));
 close(client_fd);
 //printf("Segment number recieved: %d\n", segNum);
 /* Open device */
 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = segNum * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 int type;
 client_fd = accept_connection(server_fd);
 read(client_fd, &type, sizeof(int));
 close(client_fd);

 if(type == 0) {
 /* Write segNum to address 951396 */ // TODO: THIS BAD. ONLY DO THIS DURING AUDIT and parity generation.
 if (lseek(fd, 951396 * SEGMENT_SIZE, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }
 

 memcpy(buf, &segNum, sizeof(segNum));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 }

 struct timeval start, end;
 gettimeofday(&start, NULL);

 if (pread(fd, buf, SEGMENT_SIZE, offset) == -1) { 
 perror("[pread]");
 free(buf);
 close(fd);
 return -1;
 }

 fsync(fd);

 gettimeofday(&end, NULL);
 long seconds = end.tv_sec - start.tv_sec;
 long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

 printf("Time elapsed Get segment: %ld.%06ld seconds\n", seconds, micros);


 memcpy(segData, buf, SEGMENT_SIZE);

 // printf("Segment data encrypted??\n");
 // for(int i = 0; i < SEGMENT_SIZE; i++) {
 // printf("%x", segData[i]);
 // }
 // printf("\n");

 close(fd);

 /* Send data at segNum */
 client_fd = accept_connection(server_fd);
 size_t total_sent = 0;
 while (total_sent < SEGMENT_SIZE) {
 size_t sent = write(client_fd, segData + total_sent, SEGMENT_SIZE - total_sent);
 if (sent == -1) {
 // handle error
 break;
 }
 total_sent += sent;
 }
 close(client_fd);

}

void file_init(int server_fd) 
{
 int client_fd;
 uint8_t buffer[8192];
 


 // Open storage device. ASSUME 1 File for now
 int fd; 
 if((fd = open(PATH, O_RDWR)) == -1) { // For now do not do O_DIRECT. This is not in reserved area. A simple write
 perror("[open]");
 return;
 }

 
 // Receive file name
 client_fd = accept_connection(server_fd);
 int fileNameLen = read(client_fd, buffer, FILE_NAME_LEN);
 close(client_fd);

 char fileName[fileNameLen+1];
 strncpy(fileName, buffer, fileNameLen);
 fileName[fileNameLen] = '\0';

 // Receive number of blocks
 int numParityBlocks;

 client_fd = accept_connection(server_fd);
 read(client_fd, &numParityBlocks, sizeof(numParityBlocks));
 close(client_fd);


 // Receive each block
 uint8_t blockData[BLOCK_SIZE];
 for (int i = 0; i < numParityBlocks; i++) {

 client_fd = accept_connection(server_fd);
 int bytes_received = 0;
 int bytes_left = BLOCK_SIZE;
 while (bytes_left > 0) {
 int bytes_read = read(client_fd, blockData + bytes_received, bytes_left);
 if (bytes_read < 0) {
 // handle error
 } else if (bytes_read == 0) {
 // handle disconnection
 } else {
 bytes_received += bytes_read;
 bytes_left -= bytes_read;
 }
 }
 // printf("Block %d received successfully\n", i);

 close(client_fd);
 
 // Write block to storage device
 if(write(fd, blockData, BLOCK_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 }

 // Receive each sigma
 uint8_t sigma[numParityBlocks][PRIME_LENGTH / 8];
 const int bytesPerSeg = 512;
 const int sigPerSeg = (bytesPerSeg) / (PRIME_LENGTH / 8);
 int sigCount = 0;
 for (int i = 0; i < numParityBlocks; i++) {
 
 client_fd = accept_connection(server_fd);

 if (read(client_fd, sigma[i], PRIME_LENGTH / 8) != PRIME_LENGTH / 8) {
 perror("failed to read sigma");
 exit(EXIT_FAILURE);
 }
 close(client_fd);

 /* Write sigma to storage device */
 if (write(fd, sigma[i], PRIME_LENGTH / 8) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 sigCount++;

 if (sigCount % sigPerSeg == 0) {
 // Calculate the number of bytes to write to fill the current segment
 int bytesWritten = (sigCount * (PRIME_LENGTH / 8));
 int bytesToFillSeg = bytesPerSeg - (bytesWritten % bytesPerSeg);
 if (bytesToFillSeg != bytesPerSeg) {
 uint8_t buffer[bytesToFillSeg];
 memset(buffer, 0, bytesToFillSeg);
 if (write(fd, buffer, bytesToFillSeg) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 }
 }
 }

 // Seek to next 512 byte segment
 off_t pos = lseek(fd, 0, SEEK_CUR);
 if (pos == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }
 off_t nextSegStart = ((pos / bytesPerSeg) + 1) * bytesPerSeg;
 off_t bytesToSkip = nextSegStart - pos;
 if (lseek(fd, bytesToSkip, SEEK_CUR) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }


 // Receive the tag
 Tag tag;
 
 client_fd = accept_connection(server_fd);

 if (read(client_fd, &tag, sizeof(Tag)) != sizeof(Tag)) {
 perror("failed to read tag");
 exit(EXIT_FAILURE);
 }
 close(client_fd);
 
 // Write tag to storage device.
 if (write(fd, &tag, sizeof(tag)) == -1) {
 perror("[write]");
 close(fd);
 return;
 }

 return 0;
}

void ftl_init(int server_fd) 
{
 int client_fd;
 uint8_t sgx_pubKey[64] = {0};
 uint8_t *ftl_pubKey = malloc(sizeof(uint8_t) * 64);
 
 /* Read SGX public key from server*/
 client_fd = accept_connection(server_fd);
 read(client_fd, sgx_pubKey, sizeof(uint8_t) * 64);
 close(client_fd);


 /* Send SGX public key to FTL, and recieve FTL public key */
 ftl_initial(sgx_pubKey, ftl_pubKey);

 client_fd = accept_connection(server_fd);
 write(client_fd, ftl_pubKey, sizeof(uint8_t) * 64);
 close(client_fd);

 free(ftl_pubKey);
}

void state_2(int server_fd) 
{
 int client_fd;

 int numBits = 0;

 client_fd = accept_connection(server_fd);
 int len = read(client_fd, &numBits, sizeof(int));
 close(client_fd);

 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = 951400 * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 /* Write segNum to address 951396 */
 if (lseek(fd, 951400 * SEGMENT_SIZE, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }

 memcpy(buf, &numBits, sizeof(numBits));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 

}

void receive_parity(int server_fd) {
 //printf("here?\n");

 // Open storage device. ASSUME 1 File for now
 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Receive size
 size_t size = 0;
 int client_fd = accept_connection(server_fd);
 if (read(client_fd, &size, sizeof(size)) != sizeof(size)) {
 perror("[read size]");
 close(client_fd);
 close(fd);
 return;
 }
 close(client_fd);

 // Align buffer to 2048 bytes
 uint8_t *buffer;
 if (posix_memalign((void **)&buffer, 2048, size) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 // Receive startPage
 int startPage = 0;
 client_fd = accept_connection(server_fd);
 if (read(client_fd, &startPage, sizeof(startPage)) != sizeof(startPage)) {
 perror("[read startPage]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 close(client_fd);

 //printf("start page: %d\n", startPage);
 //printf("size: %zu\n", size);

 // Receive page into buffer
 client_fd = accept_connection(server_fd);
 int bytes_received = 0;
 while (bytes_received < size) {
 int bytes_read = read(client_fd, buffer + bytes_received, size - bytes_received);
 if (bytes_read <= 0) {
 perror("[read page]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 bytes_received += bytes_read;
 }
 close(client_fd);

 if (lseek(fd, (startPage) * 2048, SEEK_SET) == -1) {
 perror("[lseek]");
 free(buffer);
 close(fd);
 return;
 }

 if (write(fd, buffer, 2048) == -1) {
 perror("[write]");
 free(buffer);
 close(fd);
 return;
 }
 fdatasync(fd);

 if (lseek(fd, (startPage) * 2048, SEEK_SET) == -1) {
 perror("[lseek]");
 free(buffer);
 close(fd);
 return;
 }

 // Loop for writing the data in segments
 
 for (int i = 0; i < (size / 4096) - 1; i++) {
 for (int j = 0; j < 2; j++) {
 usleep(1000000);
 size_t offset = 4096 + (4096 * i) + (2048 * j);
 if (offset + 2048 <= size) {
 if (write(fd, buffer + offset, 2048) == -1) {
 perror("[write]");
 free(buffer);
 close(fd);
 return;
 }
 fdatasync(fd);
 }
 }
 }

 free(buffer);
 close(fd);
}

void end_genPar(int server_fd) {
 int client_fd;

 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = 951384 * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 /* Write segNum to address 951396 */
 if (lseek(fd, offset, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }
 int temp = 0;
 memcpy(buf, &temp, sizeof(temp));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }
 
}

void write_partition(int server_fd) {
 int client_fd;

 int numBits = 0;

 client_fd = accept_connection(server_fd);
 int len = read(client_fd, &numBits, sizeof(int));
 close(client_fd);

 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 off_t offset = 951384 * SEGMENT_SIZE; /* Segment offset */
 void *buf;
 if (posix_memalign(&buf, SEGMENT_SIZE, SEGMENT_SIZE) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 /* Write segNum to address 951396 */
 if (lseek(fd, 951384 * SEGMENT_SIZE, SEEK_SET) == -1) {
 perror("[lseek]");
 close(fd);
 return;
 }

 memcpy(buf, &numBits, sizeof(numBits));
 if (write(fd, buf, SEGMENT_SIZE) == -1) {
 perror("[write]");
 close(fd);
 return;
 }

}

void write_page(int server_fd) {
 int fd;
 if ((fd = open(PATH, O_RDWR | O_DIRECT)) == -1) {
 perror("[open]");
 return;
 }

 // Align buffer to 2048 bytes
 uint8_t *buffer;
 if (posix_memalign((void **)&buffer, 2048, 2048) != 0) {
 perror("[posix_memalign]");
 close(fd);
 return;
 }

 // Receive startPage
 int pageNum = 0;
 int client_fd = accept_connection(server_fd);
 if (read(client_fd, &pageNum, sizeof(pageNum)) != sizeof(pageNum)) {
 perror("[read startPage]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 close(client_fd);

 //printf("start page: %d\n", startPage);
 //printf("size: %zu\n", size);

 // Receive page into buffer
 client_fd = accept_connection(server_fd);
 int bytes_received = 0;
 while (bytes_received < 2048) {
 int bytes_read = read(client_fd, buffer + bytes_received, 2048 - bytes_received);
 if (bytes_read <= 0) {
 perror("[read page]");
 free(buffer);
 close(client_fd);
 close(fd);
 return;
 }
 bytes_received += bytes_read;
 }
 close(client_fd);

 if (lseek(fd, (pageNum) * 2048, SEEK_SET) == -1) {
 perror("[lseek]");
 free(buffer);
 close(fd);
 return;
 }

 if (write(fd, buffer, 2048) == -1) {
 perror("[write]");
 free(buffer);
 close(fd);
 return;
 }
 fdatasync(fd);

}


main() 
{
 int server_fd, client_fd;
 server_fd = create_socket();
 uint8_t buffer[BUFFER_SIZE];

 while(1) {
 client_fd = accept_connection(server_fd);
 int stringLen = read(client_fd, buffer, FILE_NAME_LEN);
 close(client_fd);
 char command[stringLen+1];
 strncpy(command, buffer, stringLen);
 command[stringLen] = '\0';

 if(strcmp(command, "ftl_init") == 0) {
 printf("ftl init\n");
 ftl_init(server_fd);
 }
 else if(strcmp(command, "file_init") == 0) {
 printf("file_init\n");
 file_init(server_fd);
 }
 else if(strcmp(command, "get_segment") == 0) {
 printf("get segment\n");
 get_segment(server_fd);
 }
 else if(strcmp(command, "get_nonce") == 0 ) {
 printf("get nonce\n");
 get_challnum(server_fd);
 }
 else if(strcmp(command, "send_parity") == 0 ) {
 printf("recieve_parity\n");
 receive_parity(server_fd);

 }
 else if(strcmp(command, "state_2") == 0) { // TODO: should be changed to writing a signed magic number.
 // State transitions need to be better defined in FTL, in general.
 printf("enter state 2\n");
 state_2(server_fd);
 }
 else if(strcmp(command, "end_genPar") == 0) {
 printf("end genpar\n");
 end_genPar(server_fd);
 }
 else if(strcmp(command, "write_partition") == 0) {
 printf("write_partition");
 write_partition(server_fd);
 }
 else if(strcmp(command, "write_page") == 0) {
 printf("write_page");
 write_page(server_fd);
 }
 else exit(1);
 }
}