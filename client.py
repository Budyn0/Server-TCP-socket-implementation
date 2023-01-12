import socket

# create the socket
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to the server
server_address = ('localhost', 2525)
client_sock.connect(server_address)

# login
client_sock.send("login".encode())
username = input("Enter your username: ")
client_sock.send(username.encode())

while True:
    # display menu
    print("1. Send email")
    print("2. Receive emails")
    choice = input("Enter your choice: ")

    if choice == '1':
        # send an email
        from_username = username
        to = input("Enter the recipient's username: ")
        message = input("Enter the message: ")
        email = f"From: {from_username}\nTo: {to}\n{message}"
        client_sock.send(email.encode())
    elif choice == '2':
        # receive messages from other clients
        message = client_sock.recv(1024)
        print(message.decode())
    else:
        print("Invalid choice. Please try again.")

# close the socket
client_sock.close()
