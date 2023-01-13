#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>

#define PORT 2525          // port
#define MAX_CONNECTIONS 10 // max połączeń

// magazyn dla wiadomości
typedef struct
{
    char from[256];
    char to[256];
    char message[1024];
} Email;
pthread_mutex_t mailBox_mutex = PTHREAD_MUTEX_INITIALIZER;
Email mailBox[MAX_CONNECTIONS]; // Przechowywanie tablicy z wiadomościami e-maill
int mailCount = 0;              // zmienna przechowująca ilośc maili w tablicy

// magazyn dla usera
typedef struct
{
    char username[256];
    char ip[INET_ADDRSTRLEN];
    int sock_fd;
} User;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;
User users[MAX_CONNECTIONS]; // tablica użytkowników
int userCount = 0;           // przechowanie ilości użytkowników

void *handle_connection(void *fd_ptr)
{
    int fd = *((int *)fd_ptr);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    // Test if the socket is in non-blocking mode:
    if (fcntl(fd, F_GETFL) & O_NONBLOCK)
    {
        // socket is non-blocking
    }

    // Put the socket in non-blocking mode:
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0)
    {
        // handle error
    }
    User user; // zadeklarowanie user user;
               // wzięcie IP klienta
    getpeername(fd, (struct sockaddr *)&client_addr, &client_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("Connection from %s\n", client_ip);
    // Login
    if (strncmp(client_ip, "login", 5) == 0)
    {
        char username[256];
        int bytes_received = recv(fd, username, sizeof(username), 0);
        if (bytes_received > 0)
        {
            strcpy(user.username, username);
            strcpy(user.ip, client_ip);
            user.sock_fd = fd;
            pthread_mutex_lock(&users_mutex);
            users[userCount++] = user;
            pthread_mutex_unlock(&users_mutex);
            printf("%s logged in\n", username);
        }
        // wiadomość powodzenia logowania
        char success[] = "login successful\n";
        send(fd, success, strlen(success), 0);
    }

    while (1)
    {
        // otrzymanie danych od klienta
        char buffer[1024];
        int bytes_received = recv(fd, buffer, sizeof(buffer), 0);
        if (bytes_received > 0)
        {
            printf("Received %d bytes: %s\n", bytes_received, buffer);
        }
        else
        {
            // analiza maila
            Email email;
            sscanf(buffer, "From: %s\nTo: %s\n%s", email.from, email.to, email.message);

            // przypisanie maila do tablicy
            pthread_mutex_lock(&mailBox_mutex);
            mailBox[mailCount++] = email;
            pthread_mutex_unlock(&mailBox_mutex);

            // wysłanie wiadomości potwierdzającej otrzymanie maila przez serwer
            char response[] = "Mail has been received and stored";
            send(fd, response, strlen(response), 0);
        }
        // sprawdzenie czy jest mail i wysłanie go do użytkownika
        for (int i = 0; i < mailCount; i++)
        {
            if (strcmp(mailBox[i].to, user.username) == 0)
            {
                send(user.sock_fd, mailBox[i].message, sizeof(mailBox[i].message), 0);
                for (int i = 0; i < mailCount; i++)
                {
                    if (strcmp(mailBox[i].to, user.username) == 0)
                    {
                        send(fd, mailBox[i].message, sizeof(mailBox[i].message), 0);
                        for (int j = i; j < mailCount - 1; j++)
                        {
                            mailBox[j] = mailBox[j + 1];
                        }
                        mailCount--;
                        break;
                    }
                    printf("Sent email to %s\n", user.username);
                    break;
                }
                break;
            }
        }
    }
    // zamknięcie połączenia
    close(fd);
    pthread_exit(NULL);
}

int main()
{
    int sock_fd, new_sock_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char command[1024];

    // tworzenie socketu
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("socket error");
        exit(1);
    }

    // Konfiguracja adresu i portu
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // inet_addr("127.0.0.1")
    server_addr.sin_port = htons(PORT);

    // Bind socketu do adresu i portu
    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind error");
        exit(1);
    }

    // Nasłuchiwanie połączenia
    if (listen(sock_fd, MAX_CONNECTIONS) < 0)
    {
        perror("listen error");
        exit(1);
    }

    // pętla serwera
    while (1)
    {
        client_len = sizeof(client_addr);
        // akceptowanie połączenia
        new_sock_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &client_len);
        if (new_sock_fd < 0)
        {
            perror("accept error");
            continue;
        }
        // Tworzenie threda dla kazdego połączenia
        pthread_t thread;
        int ret = pthread_create(&thread, NULL, handle_connection, (void *)&new_sock_fd);
        if (ret != 0)
        {
            printf("Error creating thread: error code %d\n", ret);
            close(new_sock_fd);
        }
    }

    /* pętla komend
    while (1) {
        printf("Enter command (list, send <index>): ");
        scanf("%s", command);
        if (strcmp(command, "list") == 0) {
            // Lista e-maili
            for (int i = 0; i < mailCount; i++) {
                printf("%d: From: %s To: %s Message: %s\n", i, mailBox[i].from, mailBox[i].to, mailBox[i].message);
            }
        } else if (strncmp(command, "send", 4) == 0) {
            int index;
            sscanf(command, "send %d", &index);
            if (index >= 0 && index < mailCount) {
                // Wysłanie e-maila
                char response[1024];
                snprintf(response, sizeof(response), "From: %s To: %s Message: %s", mailBox[index].from, mailBox[index].to, mailBox[index].message);
                send(new_sock_fd, response, strlen(response), 0);
            } else {
                printf("Invalid email index\n");
            }
        }
    }
    */
    return 0;
}
