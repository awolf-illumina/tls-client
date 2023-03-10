import datetime
import OpenSSL
import os


OUTPUT_PATH = "../tls-server/source/certificates/"
ROOT_CERT_PATH = os.path.join(OUTPUT_PATH, "certificates_root_cert.h")
SERVER_CERT_PATH = os.path.join(OUTPUT_PATH, "certificates_server_cert.h")
SERVER_KEY_PATH = os.path.join(OUTPUT_PATH, "certificates_server_key.h")
X509_VERSION = 2


def main():
    # Generate Root Key Pair
    root_key_pair = OpenSSL.crypto.PKey()
    root_key_pair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate Self Signing Request for Root
    root_csr = OpenSSL.crypto.X509Req()
    root_csr.set_version(X509_VERSION)
    root_csr.get_subject().C = "US"
    root_csr.get_subject().ST = "CA"
    root_csr.get_subject().L = "San Diego"
    root_csr.get_subject().O = "Illumina"
    root_csr.get_subject().OU = "Firmware"
    root_csr.get_subject().CN = "www.ROOT.com"
    root_csr.get_subject().emailAddress = "root@illumina.com"
    root_csr.set_pubkey(root_key_pair)
    root_csr.sign(root_key_pair, "sha256")

    # Generate Root Certificate
    root_cert = OpenSSL.crypto.X509()
    root_cert.set_version(X509_VERSION)
    root_cert.set_serial_number(12345)
    root_cert.gmtime_adj_notBefore(0)
    root_cert.gmtime_adj_notAfter(365*24*60*60)
    root_cert.set_subject(root_csr.get_subject())
    root_cert.set_issuer(root_cert.get_subject())
    root_cert.set_pubkey(root_csr.get_pubkey())
    root_cert.sign(root_key_pair, "sha256")
    root_cert.add_extensions([
        OpenSSL.crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    ])
    # Generate Client Key Pair
    client_key_pair = OpenSSL.crypto.PKey()
    client_key_pair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate Signing Request for Client
    client_csr = OpenSSL.crypto.X509Req()
    client_csr.set_version(X509_VERSION)
    client_csr.get_subject().C = "US"
    client_csr.get_subject().ST = "CA"
    client_csr.get_subject().L = "San Diego"
    client_csr.get_subject().O = "Illumina"
    client_csr.get_subject().OU = "Firmware"
    client_csr.get_subject().CN = "www.HOST.com"
    client_csr.get_subject().emailAddress = "host@illumina.com"
    client_csr.set_pubkey(client_key_pair)
    client_csr.sign(root_key_pair, "sha256")

    # Generate Client Certificate
    client_cert = OpenSSL.crypto.X509()
    client_cert.set_version(X509_VERSION)
    client_cert.set_serial_number(12345)
    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(365*24*60*60)
    client_cert.set_subject(client_csr.get_subject())
    client_cert.set_issuer(root_cert.get_subject())
    client_cert.set_pubkey(client_csr.get_pubkey())
    client_cert.sign(root_key_pair, "sha256")

    # Generate Server Key Pair
    server_key_pair = OpenSSL.crypto.PKey()
    server_key_pair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate Signing Request for Server
    server_csr = OpenSSL.crypto.X509Req()
    server_csr.set_version(X509_VERSION)
    server_csr.get_subject().C = "US"
    server_csr.get_subject().ST = "CA"
    server_csr.get_subject().L = "San Diego"
    server_csr.get_subject().O = "Illumina"
    server_csr.get_subject().OU = "Firmware"
    server_csr.get_subject().CN = "www.HOST.com"
    server_csr.get_subject().emailAddress = "host@illumina.com"
    server_csr.set_pubkey(server_key_pair)
    server_csr.sign(root_key_pair, "sha256")

    # Generate Server Certificate
    server_cert = OpenSSL.crypto.X509()
    server_cert.set_version(X509_VERSION)
    server_cert.set_serial_number(12345)
    server_cert.gmtime_adj_notBefore(0)
    server_cert.gmtime_adj_notAfter(365*24*60*60)
    server_cert.set_subject(server_csr.get_subject())
    server_cert.set_issuer(root_cert.get_subject())
    server_cert.set_pubkey(server_csr.get_pubkey())
    server_cert.sign(root_key_pair, "sha256")

    # Export for Client
    open('root_cert.pem', 'wb').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, root_cert))
    open('client_key.pem', 'wb').write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, client_key_pair))
    open('client_cert.pem', 'wb').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, client_cert))

    # Export for Server
    root_cert_asn1 = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, root_cert)
    binary_to_file(ROOT_CERT_PATH, binary_to_array_string(root_cert_asn1), "ROOT_CERT_H_", "ROOT_CERT")

    cert_asn1 = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, server_cert)
    binary_to_file(SERVER_CERT_PATH, binary_to_array_string(cert_asn1), "SERVER_CERT_H_", "SERVER_CERT")

    key_asn1 = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, server_key_pair)
    binary_to_file(SERVER_KEY_PATH, binary_to_array_string(key_asn1), "SERVER_KEY_H_", "SERVER_KEY")


def binary_to_array_string(data):
    output_string = "{ \\\n"

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_values = ["0x{:02X}".format(b) for b in chunk]
        output_string += "    " + ", ".join(hex_values) + ", \\\n"
    output_string += "}"

    return output_string


def binary_to_file(filename, data_string, ifdef_name, symbol_name):
    template_string = open("template_config.h", "r").read()
    template_string = template_string.replace("{IFDEF}", ifdef_name)
    template_string = template_string.replace("{SYMBOL_NAME}", symbol_name)
    template_string = template_string.replace("{DATA}", data_string)

    output_file = open(filename, "w")
    output_file.write(template_string)
    output_file.close()


main()
