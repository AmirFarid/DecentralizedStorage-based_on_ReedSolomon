#ifndef CCOM_H
#define CCOM_H

#include <stddef.h>

#define PORT 49200
#define BUFFER_SIZE 1024


void erro(const char *msg);

int create_client_socket(void);

void connect_to_server(int client_fd);

void close_client_socket(int client_fd);

void send_data_to_server(void* data, size_t data_len);

void* receive_data_from_server(size_t data_len);

int get_counter(void);

#endif

