from Crypto.Cipher import AES, DES, ARC4, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import time

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

    return ciphertext, tag, nonce, aes_key, hmac_key, "AES"

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
    iv = des.iv
    ciphertext = des.encrypt(pad(bytes_data, DES.block_size))  # Padding to block size

    #Hmac with SHA-256 ensures data integrity by verifying the correspondence of the tag
    hmac_key = get_random_bytes(16)
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(iv + ciphertext).digest()

    return ciphertext, tag, iv, des_key, hmac_key, "DES"

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
    start_time = time.time()

    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        hmac.update(iv + ciphertext).verify(tag)

        des = DES.new(des_key, DES.MODE_CBC, iv=iv)
        plaintext = unpad(des.decrypt(ciphertext), DES.block_size)
    except (ValueError, KeyError):
        return None

    return plaintext

def RC4_encrypt(bytes_data: bytes) -> tuple:
    """
    RC4 encryption algorithm using Crypto.Cipher.ARC4.

    Args:
        bytes_data (bytes): plaintext to encrypt

    Returns:
        tuple: all information to decrypt the ciphertext
    """
    start_time = time.time()

    rc4_key = get_random_bytes(16)  # RC4 uses a variable-length key (commonly 16 bytes for security)
    rc4 = ARC4.new(rc4_key)
    ciphertext = rc4.encrypt(bytes_data)

    # Create a HMAC to ensure the integrity of the ciphertext
    hmac_key = get_random_bytes(16)
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(ciphertext).digest()

    return ciphertext, tag, None, rc4_key, hmac_key, "RC4"

def RC4_decrypt(ciphertext: bytes, tag: bytes, rc4_key: bytes, hmac_key: bytes) -> bytes:
    """
    RC4 decryption.

    Args:
        ciphertext (bytes): encrypted text by the function above
        tag (bytes): HMAC tag used to verify the ciphertext
        rc4_key (bytes): key used for RC4 encryption
        hmac_key (bytes): HMAC key used for integrity check

    Returns:
        bytes: decrypted text -> plaintext
    """

    try:
        # Verify the HMAC integrity
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        hmac.update(ciphertext).verify(tag)

        # Initialize the RC4 cipher with the same key and decrypt
        rc4 = ARC4.new(rc4_key)
        plaintext = rc4.decrypt(ciphertext)

    except (ValueError, KeyError):
        return None

    return plaintext

def generate_rsa_keys():
    """
    Generates a new RSA key pair (public and private keys).
    
    Returns:
        tuple: (public_key, private_key) as strings.
    """
    key = RSA.generate(1024)
    private_key = key.export_key().decode('utf-8') 
    public_key = key.publickey().export_key().decode('utf-8') 
    return public_key, private_key

def generate_shared_key():
    """
    Generate new shared key in hex

    Returns:
        bytes: shared_key in hex
    """
    shared_key = get_random_bytes(16)
    return shared_key.hex()

def aes_encrypt_key_for_shared(key_to_encrypt: bytes, shared_key: bytes) -> bytes:
    """
    Encrypt key to share file with shared key

    Args:
        key_to_encrypt (bytes): The key to encrypt.
        shared_key (bytes): The key used for encryption.

    Returns:
        bytes: The encrypted key (nonce + encrypted key).
    """
    nonce = get_random_bytes(8)
    aes = AES.new(shared_key, AES.MODE_CTR, nonce=nonce)
    ciphertext = aes.encrypt(key_to_encrypt)

    return nonce + ciphertext

def aes_decrypt_key_for_shared(shared_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt a key using AES with a shared key.

    Args:
        shared_key (bytes): The key used for decryption.
        ciphertext (bytes): The encrypted key (nonce + encrypted key).

    Returns:
        bytes: The decrypted key.
    """
    # Extract the nonce from the ciphertext
    nonce = ciphertext[:8]  # Extract the first 8 bytes as the nonce
    encrypted_key = ciphertext[8:]  # The rest is the encrypted key

    aes = AES.new(shared_key, AES.MODE_CTR, nonce=nonce)
    decrypted_key = aes.decrypt(encrypted_key)
    
    return decrypted_key

def encrypt_shared_key(shared_key: bytes, public_key: bytes) -> bytes:
    """
    Encrypt the shared key using the public key.

    Args:
        shared_key (bytes): The shared key to encrypt.
        public_key (bytes): The public key to use for encryption.

    Returns:
        bytes: The encrypted shared key.
    """
    try:
        # Convertir la clé publique de chaîne en clé RSA
        rsa_public_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)

        # Chiffrer la shared_key
        encrypted_shared_key = cipher_rsa.encrypt(shared_key)
        
        return encrypted_shared_key.hex()

    except ValueError as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt_shared_key(encrypted_shared_key_hex: bytes, private_key: bytes) -> bytes:
    """
    Decrypt the shared key using the private key.

    Args:
        encrypted_shared_key (bytes): The encrypted shared key to decrypt.
        private_key (bytes): The private key to use for decryption.

    Returns:
        bytes: The decrypted shared key.
    """
    try:
        if not all(c in '0123456789abcdefABCDEF' for c in encrypted_shared_key_hex):
            raise ValueError("Invalid hexadecimal format for the encrypted key.")
        
        # Convertir la clé privée de chaîne en clé RSA
        rsa_private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)

        encrypted_shared_key = bytes.fromhex(encrypted_shared_key_hex)

        if len(encrypted_shared_key) != (rsa_private_key.size_in_bytes()):
            raise ValueError("Ciphertext with incorrect length.")

        decrypted_shared_key = cipher_rsa.decrypt(encrypted_shared_key)
        return decrypted_shared_key

    except ValueError as e:
        print(f"Error during decryption: {e}")
        return None

def hash_signature(plaintext: bytes) -> bytes:
    hash_obj = SHA256.new()
    hash_obj.update(plaintext)
    return hash_obj

def encrypt_signature(file: bytes, private_key: bytes) -> bytes:
    """
    Encrypt the file hash using the private key.

    Args:
        file (bytes): The hash file to encrypt.
        private_key (bytes): The private key to use for encryption.

    Returns:
        bytes: The encrypted file.
    """
    try:
        # Convertir la clé publique de chaîne en clé RSA
        rsa_private_key = RSA.import_key(private_key)
        cipher_rsa = pkcs1_15.new(rsa_private_key)

        # Chiffrer la shared_key
        encrypted_file = cipher_rsa.sign(file)
        
        return encrypted_file.hex()

    except ValueError as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt_signature(hash_file: bytes, encrypted_file_hex: bytes, public_key: bytes) -> bytes:
    """
    Decrypt the hash file using the public key.

    Args:
        encrypted_file_hex (bytes): The encrypted file to decrypt.
        private_key (bytes): The public key to use for decryption.

    Returns:
        bytes: The decrypted shared key.
    """
    try:
        if not all(c in '0123456789abcdefABCDEF' for c in encrypted_file_hex):
            raise ValueError("Invalid hexadecimal format for the encrypted key.")
        
        # Convertir la clé privée de chaîne en clé RSA
        rsa_public_key = RSA.import_key(public_key)
        cipher_rsa = pkcs1_15.new(rsa_public_key)

        encrypted_file = bytes.fromhex(encrypted_file_hex)

        if len(encrypted_file) != (rsa_public_key.size_in_bytes()):
            raise ValueError("Ciphertext with incorrect length.")

        decrypted_shared_key = cipher_rsa.verify(hash_file,encrypted_file)
        return decrypted_shared_key

    except ValueError as e:
        print(f"Error during decryption: {e}")
        return None


def digital_signature_encrypt(ciphertext: bytes, private_key: bytes) -> bytes:
    
    hash_plaintext_SHA256 = hash_signature(ciphertext)

    hash_plaintext_hex = hash_plaintext_SHA256.hexdigest()
    
    hash_plaintext = bytes.fromhex(hash_plaintext_hex)

    encrypted_digital_signature = encrypt_signature(file=hash_plaintext_SHA256,private_key=private_key)
    
    return encrypted_digital_signature

def digital_signature_verify(hash_file: bytes,cipher_digital_signature: bytes, public_key: bytes) -> bytes:

    hash_file = hash_signature(hash_file)
    decrypted_digital_signature = decrypt_signature(hash_file=hash_file,encrypted_file_hex=cipher_digital_signature,public_key=public_key)
    
    return decrypted_digital_signature