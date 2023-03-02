import socket
import sys

IP_ADDRESS = "192.168.0.10"
PORT = 7
MESSAGE = B"ASDFLAKJSDHFLAKJSHDFLKAJSDHFLKAJSDHFLKASJHDF"
TIMEOUT = 1


def main():
    server_address = (IP_ADDRESS, PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.timeout = TIMEOUT

    sock.connect(server_address)

    sock.sendall(MESSAGE)

    data = sock.recv(len(MESSAGE))
    print(data)


main()
