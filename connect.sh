#!/bin/sh

openssl s_client -connect 192.168.0.10:11111 -state -CAfile root_cert.pem -key client_key.pem -cert client_cert.pem