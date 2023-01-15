#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>

#define PORT 2525          // portclient
#define PORT_SERVER 3525   // portserver
#define MAX_CONNECTIONS 10 // max połączeń
#define MAX_SERVERS 5      // max serverow

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

struct thread_args
{
    volatile int fd;
    char *mail_server;
};

// void *handle_client_connection(void *fd_ptr)
void *handle_client_connection(void *args)
{
    // int fd = *((int *)fd_ptr);
    struct thread_args *params = args;
    int fd = params->fd;
    char *mail = params->mail_server;

    printf("[client] New client connection thread (local mail server: %s)\n", mail);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    User user; // zadeklarowanie user user;
               // wzięcie IP klienta
    getpeername(fd, (struct sockaddr *)&client_addr, &client_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[client] Connection from %s\n", client_ip);

    // Login
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
        printf("[client] %s logged in\n", username);
    }
    // wiadomość powodzenia logowania
    char success[] = "login successful\n";
    send(fd, success, strlen(success), 0);
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

    char buffer[1024];
    while (1)
    {
        bzero(buffer, 1024);
        // otrzymanie danych od klienta
        int bytes_received = recv(fd, buffer, sizeof(buffer), 0);
        if (bytes_received > 0)
        {
            printf("[client] Received %d bytes: %s\n", bytes_received, buffer);
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
        pthread_mutex_lock(&mailBox_mutex);
        if (mailCount > 0)
        {
            //printf("[client] Mail counts %d\n", mailCount);
        }
        for (int i = 0; i < mailCount; i++)
        {
            //if (strcmp(mailBox[i].to, user.username) == 0)
            if (strstr(mailBox[i].to, user.username) != NULL)
            {
                printf("[client] New mail found to %s\n", user.username);
                send(fd, mailBox[i].message, sizeof(mailBox[i].message), 0);
                for (int j = i; j < mailCount - 1; j++) // przesunięcie o 1 indeks w lewo w talbicy po wysłaniu
                {
                    mailBox[j] = mailBox[j + 1];
                }
                mailCount--;
            }
        }
        pthread_mutex_unlock(&mailBox_mutex);
    }
    // zamknięcie połączenia
    close(fd);
    pthread_exit(NULL);
}

void *handle_server_recv_connection(void *args)
{
    // wątek połączenia recv jest oparty na połączeniu przychodzącym (accept)
    // po nawiązaniu połączenia, lokalny serwer zwraca swój adres pocztowy
    // odbieramy listę maili do @serverA.pl

    struct thread_args *params = args;
    int fd = params->fd;
    char *mail = params->mail_server;

    // ustawiamy gniazdo w tryb blokowania...
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

    char local_mail_address[256];
    strcpy(local_mail_address, mail);
    printf("[server-recv] New server recv connection thread (local mail address: %s), fd: %d.. sending mail address\n", local_mail_address, fd);

    // wyślij lokalny adres pocztowy - jestem XYZ
    int bytes_sent = send(fd, local_mail_address, strlen(local_mail_address), 0);
    printf("[server-recv] sent %d bytes\n", bytes_sent);
    if (bytes_sent < 0)
    {
        printf("[server-recv] error while sending mail address.. closing connection\n");
        close(fd);
        pthread_exit(NULL);
    }

    printf("[server-recv] Waiting for new messages from remote server to %s..\n", local_mail_address);
    while (1)
    {
        Email new_mail;
        // otrzymanie danych od klienta
        int bytes_received = recv(fd, (void *)&new_mail, sizeof(new_mail), 0);
        if (bytes_received > 0)
        {
            printf("[server-recv] Received %d bytes\n", bytes_received);

            // przypisanie maila do tablicy
            pthread_mutex_lock(&mailBox_mutex);
            mailBox[mailCount++] = new_mail;
            pthread_mutex_unlock(&mailBox_mutex);
        }

        sleep(1);
    }

    // zamknięcie połączenia
    close(fd);
    pthread_exit(NULL);
}

void *handle_server_send_connection(void *args)
{
    // wątek połączenia send jest oparty na połączeniach wychodzących (connect)

    // po połączeniu serwer zdalny musi zwrócić swój adres pocztowy, np. @serverB.pl

    //@serverB.pl iterujemy po skrzynkach, szukamy adresów pocztowych i wysyłamy te które są dla tego serwera
    // wysyłamy maile na adres pocztowy, np. @serverB.pl

    struct thread_args *params = args;
    int fd = params->fd;
    char *mail = params->mail_server;

    // set socket to the blocking mode..
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

    printf("[server-send] New server send connection thread (local mail address: %s), fd: %d\n", mail, fd);

    // get remote mail adress - z kim rozmawiam ?
    char remote_mail_address[256];
    int bytes_received = recv(fd, remote_mail_address, sizeof(remote_mail_address), 0);
    printf("[server-send] received %d bytes\n", bytes_received);
    if (bytes_received < 0)
    {
        printf("[server-send] error while receiving the remote mail address.. closing connection\n");
        close(fd);
        pthread_exit(NULL);
    }
    printf("[server-send] Connection with remote server established [ local mail address: %s, remote mail address: %s]\n", mail, remote_mail_address);

    printf("[server-send] Waiting for new messages from clients remote to %s..\n", remote_mail_address);
    while (1)
    {
        // sprawdzenie czy jest mail do tego servera.. i wysłanie go
        pthread_mutex_lock(&mailBox_mutex);
        for (int i = 0; i < mailCount; i++)
        {
            // if (strcmp(mailBox[i].to, user.username) == 0)
            if (strstr(mailBox[i].to, remote_mail_address) != NULL)
            {
                printf("[server-send] New mails to %s found.. sending\n", remote_mail_address);
                int bytes_sent = send(fd, (void *)&mailBox[i], sizeof(mailBox[i]), 0);
                printf("[server-send] New mails to %s found.. sent %d bytes\n", remote_mail_address, bytes_sent);
                for (int j = i; j < mailCount - 1; j++) // przesunięcie o 1 indeks w lewo w talbicy po wysłaniu
                {
                    mailBox[j] = mailBox[j + 1];
                }
                mailCount--;
            }
        }
        pthread_mutex_unlock(&mailBox_mutex);

        sleep(1);
    }

    // zamknięcie połączenia
    close(fd);
    pthread_exit(NULL);
}

int create_listen_socket(int port, int max_connections)
{
    int sock_fd;
    struct sockaddr_in server_addr;

    // tworzenie socketu
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        printf("[create_listen_socket, port: %d] socket error", port);
        exit(1);
    }

    if (!(fcntl(sock_fd, F_GETFL) & O_NONBLOCK))
    {
        // Put the socket in non-blocking mode:
        fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFL) | O_NONBLOCK);
    }

    // Konfiguracja adresu i portu
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind socketu do adresu i portu
    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        // printf("[create_listen_socket, port: %d] bind error", port);
        perror("bind");
        exit(1);
    }

    // Nasłuchiwanie połączenia
    if (listen(sock_fd, max_connections) < 0)
    {
        printf("[create_listen_socket, port: %d] listen error", port);
        exit(1);
    }

    printf("[create_listen_socket, port: %d] Listening started on port %d\n", port, port);

    return sock_fd;
}

int create_server_connection(char *ip, int port)
{
    int connfd;
    struct sockaddr_in servaddr;

    // tworzenie i weryfikacja gniazda
    connfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connfd == -1)
    {
        printf("[create_server_connection] connection socket creation failed...\n");
        exit(0);
    }
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(port);

    // połączenie gniazda klienta z gniazdem serwera
    if (connect(connfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        // printf("connection with the server %s:%d failed...\n", ip, port);
        close(connfd);
        return -1;
    }
    else
    {
        printf("[create_server_connection] connected to the server.. %s:%d \n", ip, port);
    }

    return connfd;
}

int main(int argc, char *argv[])
{

    int opt;
    // char *servers[MAX_SERVERS]; // [192.168.100.4, 192.168.100.5, 192.168.100.6]
    char *remote_server_ip = NULL;
    char *mail_server_address = NULL;

    while ((opt = getopt(argc, argv, "a:r:")) != -1)
    {
        switch (opt)
        {
        case 'a':
            mail_server_address = optarg;
            break;
        case 'r':
            remote_server_ip = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s [-r remote server ip]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf("------\n");
    printf("REMOTE IP ADDRESS: %s\n", remote_server_ip);
    printf("LOCAL MAIL SERVER: %s\n", mail_server_address);
    printf("------\n");

    int sock_fd_server = create_listen_socket(PORT_SERVER, MAX_CONNECTIONS);
    int sock_fd_client = create_listen_socket(PORT, MAX_CONNECTIONS);

    volatile int remote_server_connfd = 0;

    // pętla serwera
    while (1)
    {
        /**
         *   SERVER <-> SERVER
         */
        // nawiazywanie polaczenia z serverem
        if (remote_server_connfd <= 0)
        {
            printf("connecting to the remote server.. %s:%d\n", remote_server_ip, PORT_SERVER);
            remote_server_connfd = create_server_connection(remote_server_ip, PORT_SERVER);
            if (remote_server_connfd > 0)
            {
                // Tworzenie threda dla kazdego połączenia z remote serverem
                pthread_t thread;
                volatile struct thread_args args;
                args.fd = remote_server_connfd;
                args.mail_server = mail_server_address;
                int ret = pthread_create(&thread, NULL, handle_server_send_connection, (void *)&args);
                if (ret != 0)
                {
                    printf("Error creating client connection thread: error code %d\n", ret);
                    close(remote_server_connfd);
                }
            }
        }

        // akceptowanie połączenia servera
        volatile int new_server_sock_fd;
        struct sockaddr_in server_addr;
        socklen_t server_len = sizeof(server_addr);
        new_server_sock_fd = accept(sock_fd_server, (struct sockaddr *)&server_addr, &server_len);

        if (new_server_sock_fd > 0)
        {
            // Tworzenie threda dla kazdego połączenia
            pthread_t thread;
            volatile struct thread_args args;
            args.fd = new_server_sock_fd;
            args.mail_server = mail_server_address;
            int ret = pthread_create(&thread, NULL, handle_server_recv_connection, (void *)&args);
            if (ret != 0)
            {
                printf("Error creating server thread: error code %d\n", ret);
                close(new_server_sock_fd);
            }
        }

        /**
         *   CLIENT -> SERVER
         */
        // akceptowanie połączenia clienta
        volatile int new_client_sock_fd;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        new_client_sock_fd = accept(sock_fd_client, (struct sockaddr *)&client_addr, &client_len);

        if (new_client_sock_fd > 0)
        {
            // Tworzenie threda dla kazdego połączenia
            pthread_t thread;
            volatile struct thread_args args;
            args.fd = new_client_sock_fd;
            args.mail_server = mail_server_address;
            int ret = pthread_create(&thread, NULL, handle_client_connection, (void *)&args);
            if (ret != 0)
            {
                printf("Error creating client connection thread: error code %d\n", ret);
                close(new_client_sock_fd);
            }
        }

        sleep(2);
    }

    return 0;
}
