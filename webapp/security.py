from Crypto.Cipher import AES, DES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def hash_password(password: str) -> str:
    """
    Encrypt password with the hash code SHA256

    Args:
        password (str): clear password given by the user

    Returns:
        str: return the encrypt password  
    """
    hash_obj = SHA256.new()
    hash_obj.update(password.encode('utf-8'))
    return hash_obj.hexdigest()

def verify_password(stored_hash: str, password: str) -> bool:
    """
    Password verification

    Args:
        stored_hash (str): encrypt password store inside database
        password (str): password given by the user

    Returns:
        bool: return bool if the password match with the stored_hash
    """
    verification = stored_hash == hash_password(password)
    return verification

def AES_encrypt(bytes_data: bytes) -> tuple:
    """
    AES encryption algorithm using Crypto.Cipher.AES

    Args:
        bytes_data (bytes): plaintext we have to encrypt

    Returns:
        tuple: all information for decrypt the ciphertext
    """

    #Encryption using AES
    aes_key = get_random_bytes(16)
    aes = AES.new(aes_key, AES.MODE_CTR) #CounTer Mode
    nonce = aes.nonce
    ciphertext = aes.encrypt(bytes_data)

    #Hmac with SHA-256 ensures data integrity by verifying the correspondence of the tag
    hmac_key = get_random_bytes(16)
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(aes.nonce + ciphertext).digest()

    return ciphertext, tag, nonce, aes_key, hmac_key

def AES_decrypt(ciphertext: bytes, tag: bytes, nonce: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """
    AES decryption

    Args:
        ciphertext (bytes): encrypt text by the function above
        tag (bytes): tag use to encrypt AES
        nonce (bytes): nonce use to encrypt AES
        aes_key (bytes): aes_key use to encrypt AES
        hmac_key (bytes): hmac_key use to encrypt AES

    Returns:
        bytes: decrypt text -> plaintext
    """
    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        tag = hmac.update(nonce + ciphertext).verify(tag)
        cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
    except ValueError:
        return None

    return plaintext

def DES_encrypt(bytes_data: bytes) -> tuple:
    """
    DES encryption algorithm using Crypto.Cipher.DES in CBC mode.

    Args:
        bytes_data (bytes): plaintext to encrypt

    Returns:
        tuple: all information to decrypt the ciphertext
    """

    #Encryption using DES
    des_key = get_random_bytes(8)  # DES uses 8-byte (64-bit) key
    des = DES.new(des_key, DES.MODE_CBC) #Cipher-Block chaining
    iv = des.iv  # Initialization Vector
    ciphertext = des.encrypt(pad(bytes_data, DES.block_size))  # Padding to block size

    #Hmac with SHA-256 ensures data integrity by verifying the correspondence of the tag
    hmac_key = get_random_bytes(16)
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(iv + ciphertext).digest()

    return ciphertext, tag, iv, des_key, hmac_key


def DES_decrypt(ciphertext: bytes, tag: bytes, iv: bytes, des_key: bytes, hmac_key: bytes) -> bytes:
    """
    DES decryption in CBC mode.

    Args:
        ciphertext (bytes): encrypted text by the function above
        tag (bytes): HMAC tag used to verify the ciphertext
        iv (bytes): Initialization vector used to encrypt DES
        des_key (bytes): DES key used for encryption
        hmac_key (bytes): HMAC key used for integrity check

    Returns:
        bytes: decrypted text -> plaintext
    """
    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        hmac.update(iv + ciphertext).verify(tag)

        des = DES.new(des_key, DES.MODE_CBC, iv=iv)
        plaintext = unpad(des.decrypt(ciphertext), DES.block_size)
    except (ValueError, KeyError):
        return None

    return plaintext



#Store user’s private data in a database
#Refer to GDPR (EU)/UU PDP for what are considered to be private data
#Store user’s ID card image
#Store user’s PDF/DOC/XLS files
#Store user’s video files


# All stored data must be encrypted with all of these algorithms:
# AES
# RC4
# DES

# You need to use one of the non-ECB operation modes for the block cipher (i.e., CBC, CFB, OFB, CTR)