import datetime
import OpenSSL


def main():
    # Generate Root Key Pair
    root_key_pair = OpenSSL.crypto.PKey()
    root_key_pair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate Self Signing Request for Root
    root_csr = OpenSSL.crypto.X509Req()
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
    root_cert.set_serial_number(12345)
    root_cert.gmtime_adj_notBefore(0)
    root_cert.gmtime_adj_notAfter(365*24*60*60)
    root_cert.set_subject(root_csr.get_subject())
    root_cert.set_issuer(root_cert.get_subject())
    root_cert.set_pubkey(root_csr.get_pubkey())
    root_cert.sign(root_key_pair, "sha256")

    # # Generate Host Key Pair
    host_key_pair = OpenSSL.crypto.PKey()
    host_key_pair.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # Generate Self Signing Request for Host
    host_csr = OpenSSL.crypto.X509Req()
    host_csr.get_subject().C = "US"
    host_csr.get_subject().ST = "CA"
    host_csr.get_subject().L = "San Diego"
    host_csr.get_subject().O = "Illumina"
    host_csr.get_subject().OU = "Firmware"
    host_csr.get_subject().CN = "www.HOST.com"
    host_csr.get_subject().emailAddress = "host@illumina.com"
    host_csr.set_pubkey(host_key_pair)
    host_csr.sign(root_key_pair, "sha256")

    # Generate Host Certificate
    host_cert = OpenSSL.crypto.X509()
    host_cert.set_serial_number(12345)
    host_cert.gmtime_adj_notBefore(0)
    host_cert.gmtime_adj_notAfter(365*24*60*60)
    host_cert.set_subject(host_csr.get_subject())
    host_cert.set_issuer(root_cert.get_subject())
    host_cert.set_pubkey(host_csr.get_pubkey())
    host_cert.sign(root_key_pair, "sha256")

    # Export Keys/Certs
    open('root_key.pem', 'wb').write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, root_key_pair, passphrase=b'12345678'))
    open('root_cert.pem', 'wb').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, root_cert))
    open('host_key.pem', 'wb').write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, host_key_pair, passphrase=b'12345678'))
    open('host_cert.pem', 'wb').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, host_cert))


main()
