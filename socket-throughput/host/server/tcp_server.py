import socket, threading
class ClientThread(threading.Thread):

    def __init__(self, address, socket):
        threading.Thread.__init__(self)
        self.csocket = socket
        self.address = address
        print ("New connection added: ", address)

    def run(self):
        print ("Connection from : ", self.address)
        while True:
            try:
                data = self.csocket.recv(2048)
                if data:
                    print('received data from {}'.format(self.address))
                else:
                    print("client disconnected")
                    self.csocket.close()
                    break
            except OSError:
                print("client disconnected")
                self.csocket.close()
                break

LOCALHOST = "192.168.1.34"
#LOCALHOST = "127.0.0.1"
PORT = 9999
data_size = 1 * 1024
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LOCALHOST, PORT))
print("Server started on {} port {}".format(LOCALHOST, PORT))
print("Waiting for client request..")
while True:
    server.listen(1)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()
