# Zadanie 2
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def aes_encrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

key = os.urandom(16)
message = "Го в доту завтра в 22:00"
encrypted_message = aes_encrypt(key, message)
print("Зашифрованное сообщение:", encrypted_message.hex())
decrypted_message = aes_decrypt(key, encrypted_message).decode()
print("Расшифрованное сообщение:", decrypted_message)




import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def aes_encrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(key, data):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

key = os.urandom(16)

message1 = "Го в доту в 22:00"
encrypted_message1 = aes_encrypt(key, message1)
print("Зашифрованное сообщение 1:", encrypted_message1.hex())
decrypted_message1 = aes_decrypt(key, encrypted_message1).decode()
print("Расшифрованное сообщение 1:", decrypted_message1)

message2 = "Го лучше в 23:00"
encrypted_message2 = aes_encrypt(key, message2)
print("Зашифрованное сообщение 2:", encrypted_message2.hex())
block_size = 16  
modified_message2 = encrypted_message2[:-block_size] + encrypted_message1[-block_size:]
print("Модифицированное зашифрованное сообщение 2:", modified_message2.hex())
decrypted_modified_message2 = aes_decrypt(key, modified_message2)
print("Расшифрованное модифицированное сообщение 2:", decrypted_modified_message2.decode(errors='ignore'))