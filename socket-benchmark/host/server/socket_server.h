#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct socket_server {
    struct sockaddr_in address;
    int port, server_fd, new_socket, valread;
    size_t buffer_size;
};

int ree_tcp_socket_server_init(struct socket_server* s_server);
