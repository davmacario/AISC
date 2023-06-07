import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


# select hostname to connect to
# hostname = "www.python.org"
# hostname = 'www.google.com'
hostname = "www.didattica.polito.it"
# hostname = 'localhost'
# hostname = '127.0.0.1'
# hostname = "www.ietf.org"

# port number is 443 for HTTPS, use 5000 only for localhost server
portnumber = 443
# portnumber = 5000


context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# enable automatic certificate verification and load default trusted certificates of the operating system
context.verify_mode = ssl.CERT_REQUIRED
context.load_default_certs()
# disable automatic certificate verification
# this is not the recommended way of using ssl module for a client
# context.verify_mode = ssl.CERT_NONE
# load a specific trusted certificate
# context.load_verify_locations('cert_rsa_sha1.pem')
# context.load_verify_locations('cert_ecdsa_sha256.pem')

# set the minimum and maximum TLS versions that the client will negotiate
context.minimum_version = ssl.TLSVersion.TLSv1
# context.minimum_version = ssl.TLSVersion.TLSv1_2
# context.minimum_version = ssl.TLSVersion.TLSv1_3

# context.maximum_version = ssl.TLSVersion.TLSv1
context.maximum_version = ssl.TLSVersion.TLSv1_2
# context.maximum_version = ssl.TLSVersion.TLSv1_3

# uncomment this to remove ECDHE from offered cipher suites
context.set_ciphers("RSA:!ECDHE")
ciphers = context.get_ciphers()


with socket.create_connection((hostname, portnumber)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print("TLS version:", ssock.version())
        for c in ciphers:
            if c["name"] == ssock.cipher()[0]:
                print("cipher suite:", c["description"])
        cert = x509.load_der_x509_certificate(
            ssock.getpeercert(binary_form=True), default_backend()
        )
        print("peer certificate:")
        print("  version:", cert.version)
        print("  subject:", cert.subject.rfc4514_string())
        print("  issuer:", cert.issuer.rfc4514_string())
        print("  serial number:", cert.serial_number)
        print("  not valid before:", cert.not_valid_before)
        print("  not valid after:", cert.not_valid_after)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            print(
                "  RSA public key:\n",
                public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8"),
                sep="",
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            print(
                "  ECDSA public key:\n",
                public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8"),
                sep="",
            )
        else:
            print("  public key:", public_key)

        print("  signature algorithm:", cert.signature_algorithm_oid._name)
        hash_algorithm = cert.signature_hash_algorithm
        if isinstance(hash_algorithm, hashes.SHA256):
            print("  signature hash: SHA256")
        elif isinstance(hash_algorithm, hashes.SHA1):
            print("  signature hash: SHA1")
            print(
                "  WARNING: SHA1 has been deprecated, this certificate should not be trusted!"
            )
        else:
            print("  signature hash:", cert.signature_hash_algorithm)

        # uncomment this to print certificate extensions
        # print('  extensions:')
        # for ext in cert.extensions:
        #    print('    ', ext.value)

        if hostname == "127.0.0.1" or hostname == "localhost":
            # validates self-signed certificate
            issuer_public_key = cert.public_key()
        else:
            # the python ssl module does not have a function to download the current issuer certificate. we will use certificates downloaded on 21/05/2021. those may become invalid in the future.
            if hostname == "www.google.com":
                with open("GTS CA 1C3.cer", "rb") as bin_file:
                    der_data = bin_file.read()
            elif hostname == "www.didattica.polito.it":
                with open("GEANT OV RSA CA 4.cer", "rb") as bin_file:
                    der_data = bin_file.read()
            else:
                exit()
            # this will only load the public key of the issuer certificate. Actual verification should download all the chain and verify the chain up to a root certificate.
            issuer_cert = x509.load_der_x509_certificate(der_data, default_backend())
            issuer_public_key = issuer_cert.public_key()

        # validates certificate signature using issuer's public key
        try:
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                print("cannot validate signature")
                exit()
        except InvalidSignature:
            print("certificate signature invalid")
            exit()
        print("certificate signature verified")
