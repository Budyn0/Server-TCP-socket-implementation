#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h> 
#include <arpa/inet.h>

#define PORT 2525 // port 
#define MAX_CONNECTIONS 10 

typedef struct {
    char from[256];
    char to[256];
    char message[1024];
} Email;
Email mailBox[MAX_CONNECTIONS]; // We create an array to store emails
int mailCount = 0; // Variable to store the number of emails

typedef struct {
    char username[256];
    char ip[INET_ADDRSTRLEN];
    int sock_fd;
} User;

User users[MAX_CONNECTIONS]; // Array to store usernames
int userCount = 0; // Variable to store the number of usernames

void* handle_connection(void* fd_ptr) {
    int fd = *((int*)fd_ptr);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    // Get client address
    getpeername(fd, (struct sockaddr*)&client_addr, &client_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("Connection from %s\n", client_ip);

// Receive data from the client
char buffer[1024];
int bytes_received = recv(fd, buffer, sizeof(buffer), 0);
if (bytes_received > 0) {
    printf("Received %d bytes: %s\n", bytes_received, buffer);

    // Login
    if (strncmp(buffer, "login", 5) == 0) {
        char username[256];
        int bytes_received = recv(fd, username, sizeof(username), 0);
        if (bytes_received > 0) {
            User user;
            strcpy(user.username, username);
            strcpy(user.ip, client_ip);
            user.sock_fd = fd;
            users[userCount++] = user;
            printf("%s logged in\n", username);
            //send success message back
            char success[] = "login successful\n";
            send(fd, success, strlen(success), 0);
        }
    }
    else {
        // Parse the email
        Email email;
        sscanf(buffer, "From: %s\nTo: %s\n%s", email.from, email.to, email.message);

        // Assign the email to the mailBox array
        mailBox[mailCount++] = email;

        // Send a response
        char response[] = "Mail has been received and stored";
        send(fd, response, strlen(response), 0);
    }
}

// check for new emails and send them to the correct user
for (int i = 0; i < mailCount; i++) {
    for (int j = 0; j < userCount; j++) {
        if (strcmp(mailBox[i].to, users[j].username) == 0) {
            send(users[j].sock_fd, mailBox[i].message, sizeof(mailBox[i].message), 0);
            printf("Sent email to %s\n", users[j].username);
            break;
        }
    }
}

// Close the connection
close(fd);
pthread_exit(NULL);
}

int main() {
    int sock_fd, new_sock_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char command[1024];

    // Create the socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket error");
        exit(1);
    }

    // Configure the address and port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket to the address and port
    if (bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind error");
        exit(1);
    }

    // Listen for connections
    if (listen(sock_fd, MAX_CONNECTIONS) < 0) {
        perror("listen error");
        exit(1);
    }

    // Server loop
    while (1) {
        client_len = sizeof(client_addr);
        // Accept a connection
        new_sock_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &client_len);
    if (new_sock_fd < 0) {
    perror("accept error");
    continue;
    }
    
        // Create a thread for each connection
        pthread_t thread;
        int ret = pthread_create(&thread, NULL, handle_connection, (void *)&new_sock_fd);
        if(ret != 0) {
            printf("Error creating thread: error code %d\n", ret);
            close(new_sock_fd);
        }
    }

    // Command loop
    while (1) {
        printf("Enter command (list, send <index>): ");
        scanf("%s", command);
        if (strcmp(command, "list") == 0) {
            // Print the list of emails
            for (int i = 0; i < mailCount; i++) {
                printf("%d: From: %s To: %s Message: %s\n", i, mailBox[i].from, mailBox[i].to, mailBox[i].message);
            }
        } else if (strncmp(command, "send", 4) == 0) {
            int index;
            sscanf(command, "send %d", &index);
            if (index >= 0 && index < mailCount) {
                // Send the email
                char response[1024];
                snprintf(response, sizeof(response), "From: %s To: %s Message: %s", mailBox[index].from, mailBox[index].to, mailBox[index].message);
                send(new_sock_fd, response, strlen(response), 0);
            } else {
                printf("Invalid email index\n");
            }
        }
    }
    return 0;

    }

    