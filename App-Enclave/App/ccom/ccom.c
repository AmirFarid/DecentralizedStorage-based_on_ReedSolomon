#include "ccom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>

int counter = 0;

int get_counter(){
    return counter;
}

void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int create_client_socket() {
    int client_fd;

    // Create socket
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        error("socket creation failed");
    }

    return client_fd;
}

void connect_to_server(int client_fd) {
    counter ++;
	usleep(100000);
    struct sockaddr_in serv_addr;

    // Set server address and port
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr("172.16.49.187");

    // Connect to server
    if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        error("connection failed");
    }
}

void close_client_socket(int client_fd) {
    // Close the socket
    close(client_fd);
}

void send_data_to_server(void* data, size_t data_len) {
    int client_fd = create_client_socket();
    connect_to_server(client_fd);
    ssize_t total_sent = 0;
    while (total_sent < data_len) {
        ssize_t sent = write(client_fd, data + total_sent, data_len - total_sent);
        if (sent == -1) {
            // handle error
            break;
        }
        total_sent += sent;
    }
    close(client_fd);
}

void* receive_data_from_server(size_t data_len) {
    int client_fd = create_client_socket();
    connect_to_server(client_fd);
    void* data = malloc(data_len);
    ssize_t total_received = 0;
    while (total_received < data_len) {
        ssize_t received = read(client_fd, data + total_received, data_len - total_received);
        if (received == -1) {
            // handle error
            break;
        } else if (received == 0) {
            // handle end of stream
            break;
        }
        total_received += received;
    }
    close(client_fd);
    if (total_received != data_len) {
        free(data);
        return NULL;
    }
    return data;
}

