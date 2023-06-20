from flask import Flask
import ssl, socket


app = Flask(__name__)


@app.route("/")
def index():
    return "HTTPS server is running!"


if __name__ == "__main__":
    # creates a standard TLS context for a server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # set the minimum a maximum TLS versions that the server will negotiate
    context.minimum_version = ssl.TLSVersion.SSLv3

    # context.maximum_version = ssl.TLSVersion.TLSv1
    # context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    # load a certificate for the server's public key and the corresponding private key
    # context.load_cert_chain("cert_rsa_sha256.pem", "cert_rsa_sha256.key")
    context.load_cert_chain("cert_ecdsa_sha256.pem", "cert_ecdsa_sha256.key")

    # start a test HTTPS server on https://127.0.0.1:5000
    app.run(ssl_context=context)
