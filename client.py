import socket

def client():
    # Tworzenie gniazda
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Podanie adresu IP serwera
    server = input("Enter IP of the server: ")
    port = 2525

    # Łączenie z serwerem
    client_socket.connect((server, port))

    # Logowanie
    username = input("Enter username: ")
    client_socket.sendall(username.encode())
    response = client_socket.recv(1024).decode()
    print(response)

    while True:
        # Menu
        print("1. Send email")
        print("2. Receive email")
        print("3. Exit")
        choice = input("Enter your choice: ")

        # Wysyłanie maila
        if choice == '1':
            to = input("To: ")
            message = input("Message: ")
            email = "From: {}\nTo: {}\n{}".format(username, to, message)
            client_socket.sendall(email.encode())
        # Odbieranie maila
        elif choice == '2':
            data = client_socket.recv(1024)
            print("Received email: ")
            print(data.decode())
        # Wyjście z programu
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")
    # Zakończenie połączenia
    client_socket.close()

if __name__ == '__main__':
    client()
