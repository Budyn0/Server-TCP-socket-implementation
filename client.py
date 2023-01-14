import socket

# Tworzenie gniazda
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Łączenie z serwerem
server_address = ('127.0.0.1', 2525)
print('Connecting to {}:{}'.format(*server_address))
client_socket.connect(server_address)

# Logowanie
username = input('Enter your username: ')
client_socket.sendall(username.encode())

# Otrzymanie powiadomienia o pomyślnym zalogowaniu
response = client_socket.recv(1024).decode()
print(response)

while True:
    # Wyświetlenie menu
    print('1. Send email')
    print('2. Read email')
    print('3. Exit')
    choice = input('Enter your choice: ')

    # Wysłanie wiadomości e-mail
    if choice == '1':
        to = input('To: ')
        message = input('Message: ')
        email_format = 'From: {}\nTo: {}\n{}'
        email = email_format.format(username, to, message)
        client_socket.sendall(email.encode())
        print('Email sent.')
    # Odczytanie wiadomości e-mail
    elif choice == '2':
        client_socket.sendall(b'READ')
        email = client_socket.recv(1024).decode()
        print(email)
    # Wyjście
    elif choice == '3':
        client_socket.sendall(b'EXIT')
        print('Exiting...')
        break
