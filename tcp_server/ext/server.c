#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX         80
#define PORT        9999
//#define REMOTE_IP   "163.172.155.43"
#define REMOTE_IP   "127.0.0.1"

void func(int sockfd)
{
    char buff[MAX];
    int n;
    // Infinite Loop
    for (;;) {
        memset(buff, '\0', MAX);
        n = 0;

        // Read message from client and copy it in buffer
        read(sockfd, buff, sizeof(buff));
        printf("From client: %s\t To client:", buff);
        memset(buff, '\0', MAX);

        // Read input and send message to client
        /*
        while ((buff[n++] = getchar()) != '\n');
        write (sockfd, buff, sizeof(buff));

        if (strncmp("exit", buff, 4) == 0) {
            printf("Server Exit...\n");
            break;
        }
        */
    }
}

int main (int arcg, char const *argv[])
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello =  "Hello from server";

    // Creating Socket File Descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket Failed");
        exit(EXIT_FAILURE);
    }

    // Attaching to port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                                                            sizeof(opt))) {
        perror("Set Socket Options Failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT );

    /*
    if(inet_pton(AF_INET, REMOTE_IP, &address.sin_addr.s_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
    */

    if (bind(server_fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("Bind Failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("Listen Failed");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *) &address,
                    (socklen_t *) &addrlen)) < 0) {
        perror("Accept Failed");
        exit(EXIT_FAILURE);
    }
    
    // Chatting between server and client
    func(new_socket);

    // Close the socket when finished
    close(server_fd);

    return 0;
}

