# socket_echo_server.py
import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
data_size = 1024 * 1024

# Bind the socket to the port
server_address = ('127.0.0.1', 9999)
print('starting up TCP server on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for TCP a connection')
    connection, client_address = sock.accept()
    print('TCP connection from', client_address)
    # Receive the data in small chunks and retransmit it
    # while (num_send > 0):
    while True:
        try:
            data = connection.recv(data_size + 1)
            if data:
                print('received {!r}'.format(data))
            else:
                print("client disconnected")
                connection.close()
                break
        except OSError:
            print("client disconnected")
            connection.close()
            break
