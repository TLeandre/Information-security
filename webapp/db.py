import sqlite3
from sqlite3 import Error
import security

### --- 
# User section
### --- 

def connect(email: str, password: str) -> int:
  """
  Connection verification

  Args:
      email (str): email of the user
      password (str): password of the user

  Returns:
      int: information about user id or -1 if the connexion failed
  """
  try:
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()
    cursor.execute("""SELECT CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,PASSWORD,ID_USER  FROM USERS """ )
    mails = cursor.fetchall()
    for mail in mails:
      if security.RC4_decrypt(mail[0],mail[1],mail[2],mail[3]).decode('utf-8') == email:
        password_find = mail[4]
        id_usr = mail[5]
    con.close()    
    if (security.verify_password(password_find, password)):
      return id_usr
    else:
      return -1
  except Exception as e:
    print(f"Erreur : {e}")
    return -1
  finally:
    if con:
      con.close()
    else:
      error = "Oh shucks, something is wrong here."
    
def sign_in(name: str, surname: str, email: str, password: str) -> int:
    """
    Sign up user inside database

    Args:
        name (str): name of the user
        surname (str): surname of the user
        email (str): email of the user
        password (str): password of the user

    Returns:
        int: if the sign up failed or not
    """
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()
    cursor.execute("""SELECT CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY  FROM USERS """ )
    mails = cursor.fetchall()
    mail_valid = 1
    for mail in mails:
      if security.RC4_decrypt(mail[0],mail[1],mail[2],mail[3]).decode('utf-8') == email:
        mail_valid = 0

    if mail_valid == 1:
        #generate public and private key
        public_key, private_key = security.generate_rsa_keys()
        shared_key = security.generate_shared_key()

        CIPHER_NAME,NAME_TAG,NAME_INIT_VALUE,NAME_ALGO_KEY,NAME_HMAC_KEY,NAME_ALGO = security.RC4_encrypt(name.encode('utf-8'))
        CIPHER_SURNAME,SURNAME_TAG,SURNAME_INIT_VALUE,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY,SURNAME_ALGO = security.RC4_encrypt(surname.encode('utf-8'))
        CIPHER_EMAIL,EMAIL_TAG,EMAIL_INIT_VALUE,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,EMAIL_ALGO = security.RC4_encrypt(email.encode('utf-8'))
        pw = password
        cursor.execute("""INSERT INTO USERS(CIPHER_NAME,NAME_TAG,NAME_ALGO_KEY,NAME_HMAC_KEY,NAME_ALGO,CIPHER_SURNAME,SURNAME_TAG,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY,SURNAME_ALGO,CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,EMAIL_ALGO,PASSWORD, PUBLIC_KEY, PRIVATE_KEY, SHARED_KEY) 
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""" , (CIPHER_NAME,NAME_TAG,NAME_ALGO_KEY,NAME_HMAC_KEY,NAME_ALGO, CIPHER_SURNAME,SURNAME_TAG,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY,SURNAME_ALGO, CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,EMAIL_ALGO,pw,public_key, private_key, shared_key))
        con.commit()
        con.close()
        return 0
    else :
        con.close()
        return -1 
    
def get_user(id: int) -> list:
  """
  User informations 

  Args:
      id (int): id of the user

  Returns:
      list: all information about the logged-in user 
  """
  con = sqlite3.connect('database.db')
  cur = con.cursor()
  sql = """SELECT CIPHER_NAME,NAME_TAG,NAME_ALGO_KEY,NAME_HMAC_KEY, CIPHER_SURNAME,SURNAME_TAG,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY, CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY
           FROM USERS
           WHERE ID_USER = ?"""
  cur.execute(sql, (id,))
  infos = cur.fetchall()
  infos_decrypt = [
    security.RC4_decrypt(infos[0][0],infos[0][1],infos[0][2],infos[0][3]).decode('utf-8'),
    security.RC4_decrypt(infos[0][4],infos[0][5],infos[0][6],infos[0][7]).decode('utf-8'),
    security.RC4_decrypt(infos[0][8],infos[0][9],infos[0][10],infos[0][11]).decode('utf-8'),
  ]
  return infos_decrypt

def get_other_users_emails(current_user_id: int) -> list:
    """
    Retrieves the emails and IDs of all users except the currently connected user.

    Args:
        current_user_id (int): The ID of the currently connected user.

    Returns:
        list: A list of tuples containing user IDs and emails.
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()

        sql = """SELECT ID_USER, CIPHER_EMAIL, EMAIL_TAG, EMAIL_ALGO_KEY, EMAIL_HMAC_KEY
                 FROM USERS
                 WHERE ID_USER != ?"""
        cur.execute(sql, (current_user_id,))
        encrypted_emails = cur.fetchall()
        con.close()

        user_emails = []
    
        for row in encrypted_emails:
            user_id = row[0]
            decrypted_email = security.RC4_decrypt(row[1], row[2], row[3], row[4]).decode('utf-8')
            user_emails.append((user_id, decrypted_email))
        
        return user_emails
    
    except sqlite3.Error as error:
        print("[INFO] : Failed to retrieve user emails : ", error)
        return []

### --- 
# Files section
### --- 
    
def insert_into_database(id: int, file_path_name: str, ciphertext: bytes, tag: bytes, init_value: bytes, algo_key: bytes, hmac_key: bytes, algo: bytes) -> None: 
  """
  Insert data into database

  Args:
      id (int): id of the user
      file_path_name (str): file name
      ciphertext (bytes): ciphertext used
      tag (bytes): tag used
      init_value (bytes): init_value used
      algo_key (bytes): algo_key used
      hmac_key (bytes): hmac_key used
      algo (bytes): algo used

  """
  try:
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    sql = '''INSERT INTO FILES(ID_USER, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_INIT_VALUE, ALGO_KEY, HMAC_KEY, ALGO)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?)'''
    cur.execute(sql, (id, file_path_name, ciphertext, tag, init_value, algo_key, hmac_key, algo))
    con.commit()
  except Error as e:
    print(e)  
  finally: 
    if con:
      con.close()
    else:
      error = "Oh shucks, something is wrong here."

def get_files(id: int) -> list:
  """
  Retrieve all documents associated with a user 

  Args:
      id (int): id of the user

  Returns:
      list: all documents and information associated
  """
  con = sqlite3.connect('database.db')
  cur = con.cursor()
  sql = """SELECT ID_FILES, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_INIT_VALUE, ALGO_KEY, HMAC_KEY, ALGO
           FROM FILES
           WHERE ID_USER = ?"""
  cur.execute(sql, (id,))
  files = cur.fetchall()

  return files


### --- 
# Connection
### --- 

def connection_request_exists(requester_id: int, receiver_id: int) -> bool:
    """
    Check if a connection request already exists between two users.

    Args:
        requester_id (int): ID of the user who sent the request.
        receiver_id (int): ID of the user who received the request.

    Returns:
        bool: True if the request exists (either confirmed or not), False otherwise.
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''SELECT COUNT(*) FROM CONNECTIONS 
                 WHERE ID_REQUESTER = ? AND ID_RECEIVER = ?'''
        cur.execute(sql, (requester_id, receiver_id))
        count = cur.fetchone()[0]
        con.close()
        return count > 0  # True if count is greater than 0
    except sqlite3.Error as error:
        print("[INFO] : Failed to check connection request existence: ", error)
        return False

def add_connection_request(requester_id: int, receiver_id: int) -> None:
    """
    Add a connection request to the CONNECTIONS table.

    Args:
        requester_id (int): ID of the user sending the request.
        receiver_id (int): ID of the user receiving the request.
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''INSERT INTO CONNECTIONS (ID_REQUESTER, ID_RECEIVER, IS_CONFIRMED)
                 VALUES (?, ?, ?)'''
        cur.execute(sql, (requester_id, receiver_id, 0))  # IS_CONFIRMED is set to 0 (not confirmed)
        con.commit()
        con.close()
        print(f"[INFO] :Connection request from user {requester_id} to user {receiver_id} added successfully.")
    except sqlite3.Error as error:
        print("[INFO] : Failed to add connection request: ", error)

def get_connection_requests(user_id: int) -> list:
    """
    Retrieve all connection requests received by the user.

    Args:
        user_id (int): ID of the user receiving the requests.

    Returns:
        list: A list of tuples containing (ID_REQUESTER, EMAIL) for each request.
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''SELECT C.ID_CONNECTION, C.ID_REQUESTER, U.CIPHER_EMAIL, U.EMAIL_TAG, U.EMAIL_ALGO_KEY, U.EMAIL_HMAC_KEY
                 FROM CONNECTIONS C
                 JOIN USERS U ON C.ID_REQUESTER = U.ID_USER
                 WHERE C.ID_RECEIVER = ? AND C.IS_CONFIRMED = 0'''  # Change IS_CONFIRMED to your requirement
        cur.execute(sql, (user_id,))
        requests = cur.fetchall()
        con.close()

        decrypted_requests = []
        for req in requests:
            email = security.RC4_decrypt(req[2], req[3], req[4], req[5]).decode('utf-8')
            decrypted_requests.append((req[0], email))  # (ID_CONNECTION, DECRYPTED_EMAIL)

        return decrypted_requests
    except sqlite3.Error as error:
        print("[INFO] : Failed to retrieve connection requests: ", error)
        return []
    
def get_requester_id(connection_id: int) -> int:
    """
    Retrieve the requester ID based on the connection ID.

    Args:
        connection_id (int): The ID of the connection.

    Returns:
        int: The ID of the requester or -1 if not found.
    """
    try:
      con = sqlite3.connect('database.db', check_same_thread=False)
      cursor = con.cursor()
      cursor.execute("SELECT ID_REQUESTER FROM CONNECTIONS WHERE ID_CONNECTION = ?", (connection_id,))
      result = cursor.fetchone()
      con.close()
      return result[0]  # ID_REQUESTER
    except:
        return -1
    
def accept_connection_request(id_connection: int) -> None:
    """
    Accept a connection request by updating the connection in the database.

    Args:
        id_connection (int): ID of the connection request.
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''UPDATE CONNECTIONS
                 SET IS_CONFIRMED = 1
                 WHERE ID_CONNECTION = ? AND IS_CONFIRMED = 0'''
        cur.execute(sql, (id_connection,))
        con.commit()
        con.close()
    except sqlite3.Error as error:
        print("[INFO] : Failed to accept connection request: ", error)

def deny_connection_request(id_connection: int) -> None:
    """
    Deny a connection request by deleting it from the database.

    Args:
        id_connection (int): ID of the connection request.
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''DELETE FROM CONNECTIONS
                 WHERE ID_CONNECTION = ?'''
        cur.execute(sql, (id_connection,))
        con.commit()
        con.close()
    except sqlite3.Error as error:
        print("[INFO] : Failed to deny connection request: ", error)

def get_confirmed_connections_as_requester(user_id: int) -> list:
    """
    Retrieve confirmed connections for the given user where they are the requester.

    Args:
        user_id (int): ID of the user.

    Returns:
        list: List of tuples containing (connection_id, receiver_email).
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''SELECT C.ID_CONNECTION, U.CIPHER_EMAIL, U.EMAIL_TAG, U.EMAIL_ALGO_KEY, U.EMAIL_HMAC_KEY
                 FROM CONNECTIONS C
                 JOIN USERS U ON C.ID_RECEIVER = U.ID_USER
                 WHERE C.ID_REQUESTER = ? AND C.IS_CONFIRMED = 1'''
        cur.execute(sql, (user_id,))
        connections = cur.fetchall()
        con.close()

        decrypted_connections = []
        for conn in connections:
            email = security.RC4_decrypt(conn[1], conn[2], conn[3], conn[4]).decode('utf-8')
            decrypted_connections.append((conn[0], email))  # (ID_CONNECTION, DECRYPTED_EMAIL)

        return decrypted_connections
    except sqlite3.Error as error:
        print("[INFO] : Failed to retrieve confirmed connections as requester: ", error)
        return []
    
def get_confirmed_connections_as_receiver(user_id: int) -> list:
    """
    Retrieve confirmed connections for the given user where they are the receiver.

    Args:
        user_id (int): ID of the user.

    Returns:
        list: List of tuples containing (connection_id, requester_email).
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        sql = '''SELECT C.ID_CONNECTION, U.CIPHER_EMAIL, U.EMAIL_TAG, U.EMAIL_ALGO_KEY, U.EMAIL_HMAC_KEY, U.ID_USER
                 FROM CONNECTIONS C
                 JOIN USERS U ON C.ID_REQUESTER = U.ID_USER
                 WHERE C.ID_RECEIVER = ? AND C.IS_CONFIRMED = 1'''
        cur.execute(sql, (user_id,))
        connections = cur.fetchall()
        con.close()

        decrypted_connections = []
        for conn in connections:
            email = security.RC4_decrypt(conn[1], conn[2], conn[3], conn[4]).decode('utf-8')
            decrypted_connections.append((conn[0], conn[5], email))  # (ID_CONNECTION, DECRYPTED_EMAIL)

        return decrypted_connections
    except sqlite3.Error as error:
        print("[INFO] : Failed to retrieve confirmed connections as receiver: ", error)
        return []

def share_documents(receiver_id: int, requester_id: int) -> None:
    """
    Share documents from the requester to the receiver.
    
    Args:
        receiver_id (int): ID of the user receiving the shared documents.
        requester_id (int): ID of the user sharing the documents.
    """
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()

    try:
        # Récupérer la shared_key de l'utilisateur receveur
        cursor.execute("SELECT SHARED_KEY FROM USERS WHERE ID_USER = ?", (receiver_id,))
        shared_key_hex = cursor.fetchone()
        print("shared_key_hex", shared_key_hex)
        if shared_key_hex is None:
            print("Shared key not found.")
            return
        
        #Récupérer la clé public que l'utilisateur demandeur
        cursor.execute("SELECT PUBLIC_KEY FROM USERS WHERE ID_USER = ?", (requester_id,))
        public_key = cursor.fetchone()
        print("public_key", public_key)
        if public_key is None:
            print("Public key not found.")
            return
        
        shared_key = bytes.fromhex(shared_key_hex[0])  # Convertir en bytes

        # Sélectionner les fichiers à partager
        cursor.execute("SELECT ID_FILES, FILE_NAME, CIPHER_FILE, ALGO_KEY, FILE_TAG, FILE_INIT_VALUE, HMAC_KEY FROM FILES WHERE ID_USER = ? AND ALGO = 'AES'", (receiver_id,))
        files_to_share = cursor.fetchall()

        for file in files_to_share:
            file_id, file_name, cipher_file, algo_key, file_tag, file_init_value, hmac_key = file
            
            # Chiffrer l'ALGO_KEY avec la shared_key
            encrypted_algo_key = security.aes_encrypt_key_for_shared(algo_key, shared_key)

            # Insérer dans SHARED_FILE
            cursor.execute("""INSERT INTO SHARED_FILES (ID_REQUESTER, ID_RECEIVER , FILE_NAME, CIPHER_FILE, ALGO_KEY, FILE_TAG, FILE_INIT_VALUE, HMAC_KEY, ALGO)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                           (requester_id, receiver_id, file_name, cipher_file, encrypted_algo_key, file_tag, file_init_value, hmac_key, "AES"))
        
        con.commit()

        encrypted_shared_key = security.encrypt_shared_key(shared_key, public_key[0])
        return encrypted_shared_key

    except sqlite3.Error as error:
        print("[INFO] : Failed to share documents: ", error)
        return 0
    finally:
        con.close()

def get_shared_documents(requester_id: int) -> list:
    """
    Retrieve the names of users who have shared documents with the requester, their associated files,
    and decrypt their emails.

    Args:
        requester_id (int): ID of the user requesting the shared documents.

    Returns:
        list: A list of tuples containing user names, shared file names, and decrypted emails.
    """
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()
    
    try:
        # Requête pour récupérer les fichiers partagés avec les utilisateurs
        cursor.execute("""
            SELECT u.CIPHER_EMAIL, u.EMAIL_TAG, u.EMAIL_ALGO_KEY, u.EMAIL_HMAC_KEY, 
                   sf.FILE_NAME, sf.CIPHER_FILE, sf.FILE_TAG, sf.FILE_INIT_VALUE, 
                   sf.ALGO_KEY, sf.HMAC_KEY, sf.ALGO
            FROM SHARED_FILES sf
            JOIN USERS u ON sf.ID_RECEIVER = u.ID_USER
            WHERE sf.ID_REQUESTER = ?
        """, (requester_id,))
        
        shared_documents = cursor.fetchall() 
        decrypted_documents = []

        # Décrypter les e-mails et associer les informations
        for row in shared_documents:
            cipher_email = row[0]
            email_tag = row[1]
            email_algo_key = row[2]
            email_hmac_key = row[3]
            decrypted_email = security.RC4_decrypt(cipher_email, email_tag, email_algo_key, email_hmac_key).decode('utf-8')

            file_name = row[4]
            cipher_file = row[5]
            file_tag = row[6]
            file_init_value = row[7]
            algo_key = row[8]
            hmac_key = row[9]
            algo = row[10]

            # Ajout à la liste des documents déchiffrés
            decrypted_documents.append((decrypted_email, file_name, cipher_file, file_tag, file_init_value, algo_key, hmac_key, algo))

        return decrypted_documents

    except sqlite3.Error as error:
        print("[INFO] : Failed to retrieve shared documents: ", error)
        return []
    finally:
        con.close()

import sqlite3

def get_private_key(user_id: int) -> bytes:
    """
    Retrieve the private key of the specified user from the database.

    Args:
        user_id (int): The ID of the user whose private key is to be retrieved.

    Returns:
        bytes: The private key of the user, or None if not found.
    """
    try:
        con = sqlite3.connect('database.db')
        cursor = con.cursor()

        # Requête pour récupérer la clé privée de l'utilisateur
        cursor.execute("SELECT PRIVATE_KEY FROM USERS WHERE ID_USER = ?", (user_id,))
        result = cursor.fetchone()
        private_key_hex = result[0]

        return private_key_hex

    except sqlite3.Error as error:
        print("[INFO] : Failed to retrieve private key: ", error)
        return None
    finally:
        con.close()

def delete_shared_documents(id_receiver: int, id_requester: int) -> None:
    """
    Delete all shared documents from the SHARED_FILES table based on receiver and requester IDs.

    Args:
        id_receiver (int): The ID of the user receiving the shared documents.
        id_requester (int): The ID of the user who shared the documents.
    """
    try:
        con = sqlite3.connect('database.db')
        cursor = con.cursor()

        # Suppression des documents partagés en fonction des ID spécifiés
        cursor.execute("""
            DELETE FROM SHARED_FILES 
            WHERE ID_RECEIVER = ? AND ID_REQUESTER = ?
        """, (id_receiver, id_requester))
        
        con.commit()  # Confirmer les changements
        print(f"Documents partagés supprimés pour ID_REQUESTER = {id_requester} et ID_RECEIVER = {id_receiver}.")
    
    except sqlite3.Error as error:
        print("[INFO] : Échec de la suppression des documents partagés : ", error)
    
    finally:
        con.close()