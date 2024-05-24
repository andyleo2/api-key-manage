from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64


class Rsa:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.crypto_hash = hashes.SHA256()  # Default hash
        self.key_format = 'PKCS8'  # Default format

    def setPriKey(self, str_private_key):
        private_key = load_pem_private_key(
            str_private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        self.private_key = private_key

    def setPubKey(self, str_public_key):
        public_key = load_pem_public_key(
            str_public_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        self.public_key = public_key

    def setCryptoHash(self, hash_algorithm):
        if "sha224" == hash_algorithm:
            crypto_hash = hashes.SHA224()
        elif "sha256" == hash_algorithm:
            crypto_hash = hashes.SHA256()
        elif "sha384" == hash_algorithm:
            crypto_hash = hashes.SHA384()
        elif "sha512" == hash_algorithm:
            crypto_hash = hashes.SHA512()
        else:
            crypto_hash = hashes.SHA256()
        self.crypto_hash = crypto_hash

    def setKeyFmt(self, key_format):
        self.key_format = key_format

    def generate_rsa_key(self, bits=2048, key_format='PKCS8'):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )

        if key_format == 'PKCS1':
            self.public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1
            )
        elif key_format == 'PKCS8':
            self.public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        self.key_format = key_format

    def sign_data(self, data):
        chosen_padding = padding.PKCS1v15()
        # if self.key_format == 'PKCS1':
        #     chosen_padding = padding.PKCS1v15()
        # elif self.key_format == 'PKCS8':
        #     chosen_padding = padding.PSS(
        #         mgf=padding.MGF1(self.crypto_hash),
        #         salt_length=padding.PSS.MAX_LENGTH
        #     )

        # print("prikey:", self.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        #                                                 serialization.NoEncryption()))
        signature = self.private_key.sign(
            data,
            chosen_padding,
            self.crypto_hash
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, data, signature):
        # if self.key_format == 'PKCS1':
        #     chosen_padding = padding.PKCS1v15()
        # elif self.key_format == 'PKCS8':
        #     chosen_padding = padding.PSS(
        #         mgf=padding.MGF1(self.crypto_hash),
        #         salt_length=padding.PSS.MAX_LENGTH
        #     )
        chosen_padding = padding.PKCS1v15()
        signature = base64.b64decode(signature)
        try:
            self.private_key.public_key().verify(
                signature,
                data,
                chosen_padding,
                self.crypto_hash
            )
            return True
        except Exception as e:
            print("Verification failed:", str(e))
            return False


if __name__ == "__main__":
    # Example usage
    obj = Rsa()
    obj.generate_rsa_key(2048, 'PKCS8')
    data = b"Hello, world!"
    signature = obj.sign_data(data)
    print("Signature:", signature)

    # Verify the signature
    verification_result = obj.verify_signature(data, signature)
    print("Signature verified:", verification_result)
