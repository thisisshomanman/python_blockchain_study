# import hashlib
#
#
# hash_hello = hashlib.sha256(b"hello").hexdigest()
# hash_hallo = hashlib.sha256(b"hallo").hexdigest()
# hash_helloworld = hashlib.sha256(b"hello world!").hexdigest()
#
# print(hash_hello)
# print(hash_hallo)
# print(hash_helloworld)


#private key
import os
import binascii
import ecdsa

private_key = os.urandom(32)
# print(private_key)
# print(binascii.hexlify(private_key))
public_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1).verifying_key.to_string()

print(binascii.hexlify(private_key))
print(binascii.hexlify(public_key))