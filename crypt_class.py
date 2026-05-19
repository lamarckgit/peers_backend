import base64
import binascii
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

class SafeXSCrypt:
    def __init__(self, seed, totp_secret, constants):
        self._seed = seed
        self._totp_secret = totp_secret
        # Get private key from the passed-in constants dict
        private_key_bytes = binascii.unhexlify(constants["PRIVATE_KEY"])
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = self._private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self._public_key_str = base64.b64encode(public_key_bytes).decode("utf-8")
        aes_key = self._public_key_str[:16]

        iv = bytearray(16)
        self._aes_cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, iv)

    @property
    def aes_cipher(self):
        return self._aes_cipher

    @property
    def private_key(self):
        return self._private_key

    @property
    def seed(self):
        return self._seed

    @property
    def totp_secret(self):
        return self._totp_secret

    @property
    def public_key_str(self):
        return self._public_key_str

    # @staticmethod
    # def get_public_key_str(self):
    #     self.public_key_str = base64.b64encode(
    #         self.public_key.public_bytes(
    #             encoding=serialization.Encoding.Raw,
    #             format=serialization.PublicFormat.Raw
    #         )
    #     ).decode('utf-8')
    #     return self.public_key_str

    # If you want a getter as a staticmethod, but that's not idiomatic
    # You can just use the property above

# import base64
# from Crypto.Cipher import AES
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# from cryptography.hazmat.primitives import serialization
# import binascii
# from constants import Constants
#
# class SafeXSCrypt:
#
#     def __init__(self, seed, totp_secret):
#         self._seed = seed
#         self._totp_secret = totp_secret
#         #private_key = ed25519.SigningKey(PRIVATE_KEY, encoding='hex')
#         private_key_bytes = binascii.unhexlify(Constants.PRIVATE_KEY)
#         self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
#         public_key = self.private_key.public_key()
#         public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
#         self._public_key_str = (base64.b64encode(public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
#                                 .decode('utf-8'))
#         public_key_base64 = base64.b64encode(public_key_bytes).decode("utf-8") #"IYWTPXY11OMn9lDxhoiAB7xDAvfAthKYtTooZsMbQWY=" #base64.b64encode(public_key_bytes).decode("utf-8")
#         aes_key = public_key_base64[:16]
#
#         iv = bytearray(16)
#         self._aes_cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, iv)
#
#     @property
#     def aes_cipher(self):
#         return self._aes_cipher
#     @property
#     def private_key(self):
#         return self._private_key
#     @property
#     def seed(self):
#         return self._seed
#     @property
#     def totp_secret(self):
#         return self._totp_secret

    # @staticmethod
    # def get_public_key_str(self):
    #     self.public_key_str = base64.b64encode(
    #         self.public_key.public_bytes(
    #             encoding=serialization.Encoding.Raw,
    #             format=serialization.PublicFormat.Raw
    #         )
    #     ).decode('utf-8')
    #     return self.public_key_str
