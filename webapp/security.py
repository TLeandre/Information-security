from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

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

    aes_key = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    aes = AES.new(aes_key, AES.MODE_CTR)
    nonce = aes.nonce
    ciphertext = aes.encrypt(bytes_data)

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

    print(type(plaintext))
    return plaintext