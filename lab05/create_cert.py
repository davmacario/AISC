import socket

def gen_self_signed_cert(key='RSA', hash='SHA1'):
    """generate a self signed certificate"""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    # this is a self-signed certificate, the issuer name is the same as the subject name
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"), x509.NameAttribute(NameOID.LOCALITY_NAME, u"Torino"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AISC"), x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])

    one_day = datetime.timedelta(1, 0, 0)
    if key == 'RSA':
        # generates an RSA key pair with desired parameters
        private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend())
    elif key == 'ECDSA':
        # generates an ECDSA key pair with desired parameters
        private_key = ec.generate_private_key(
                curve=ec.SECP256R1,
                backend=default_backend())
    else:
        raise ValueError('key can only be RSA or ECDSA')
    public_key = private_key.public_key()

    # fill certificate entries
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    # certificate is valid for 5 years starting from yesterday
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day*365*5))
    builder = builder.serial_number(x509.random_serial_number())
    # the certificate links this public key to the subject name
    builder = builder.public_key(public_key)
    # this is used to match the certificate with alternative names for the subject
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
    # this is not a CA's certificate and cannot be used to sign other certificates
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    # Note: the certificate is signed with the private key corresponding to the certificate's public key. This is true only for self-signed certificates. A standard certificate should be signed with the private key of a CA or a private key corresponding to the public key of a higher level certificate.
    if hash == 'SHA256':
        # This will sign the certificate using SHA256.
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    elif hash == 'SHA1':
        # This will sign the certificate using SHA1. Several parties may refuse certificates signed with SHA1 since the hash function is considered weak.
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA1(), backend=default_backend())
    else:
        raise ValueError('hash can only be SHA1 or SHA256')

    return (certificate.public_bytes(serialization.Encoding.PEM), private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))



if __name__ == '__main__':
    cert, key = gen_self_signed_cert(key='RSA',hash='SHA1')
    with open("cert_rsa_sha1.pem", "wb") as bin_file:
        bin_file.write(cert)
    with open("cert_rsa_sha1.key", "wb") as bin_file:
        bin_file.write(key)
        
    cert, key = gen_self_signed_cert(key='RSA',hash='SHA256')
    with open("cert_rsa_sha256.pem", "wb") as bin_file:
        bin_file.write(cert)
    with open("cert_rsa_sha256.key", "wb") as bin_file:
        bin_file.write(key)
    
    cert, key = gen_self_signed_cert(key='ECDSA',hash='SHA1')
    with open("cert_ecdsa_sha1.pem", "wb") as bin_file:
        bin_file.write(cert)
    with open("cert_ecdsa_sha1.key", "wb") as bin_file:
        bin_file.write(key)
    
    cert, key = gen_self_signed_cert(key='ECDSA',hash='SHA256')
    with open("cert_ecdsa_sha256.pem", "wb") as bin_file:
        bin_file.write(cert)
    with open("cert_ecdsa_sha256.key", "wb") as bin_file:
        bin_file.write(key)

