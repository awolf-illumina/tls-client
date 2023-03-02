import socket
import ssl


IP_ADDRESS = "192.168.0.10"
PORT = 11111
MESSAGE = b"ASDFLAKJSDHFLAKJSHDFLKAJSDHFLKAJSDHFLKASJHDF"
TIMEOUT = 1


def main():
    # PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.VerifyMode.CERT_NONE

    # Create Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        with context.wrap_socket(sock, server_hostname=IP_ADDRESS) as ssock:
            ssock.settimeout(1)
            ssock.connect((IP_ADDRESS, PORT))
            ssock.write(MESSAGE)
            data = ssock.read()
            print(data)


main()
