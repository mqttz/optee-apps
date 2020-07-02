# socket_echo_server.py
import socket
import sys
import threading

class ClientThread(threading.Thread):

    def __init__(self, socket, thread_id):
        threading.Thread.__init__(self)
        self.socket = socket
        self.id = thread_id
        print('starting up UDP server #{} on {} port {}'.format(thread_id, *server_address))

    def run(self):
        data_size = 1 * 1024
        while True:
            # Wait for a connection
            print('waiting for a UDP connection at thread #{}'.format(self.id))
            data, client_address = self.socket.recvfrom(data_size + 1)
            print('UDP connection from', client_address)
            print('received data from {} at {}'.format(client_address, self.id))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('127.0.0.1', 9980)
sock.bind(server_address)
for i in range(4):
    new_th = ClientThread(sock, i)
    new_th.start()
