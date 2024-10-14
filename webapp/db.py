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
    #cursor.execute("""SELECT CIPHER_EMAIL FROM USERS WHERE CIPHER_EMAIL = '%s' """ % (str(email)))
    cursor.execute("""SELECT CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY  FROM USERS """ )
    mails = cursor.fetchall()
    mail_valid = 1
    for mail in mails:
      if security.RC4_decrypt(mail[0],mail[1],mail[2],mail[3]).decode('utf-8') == email:
        mail_valid = 0

    if mail_valid == 1:
        CIPHER_NAME,NAME_TAG,NAME_INIT_VALUE,NAME_ALGO_KEY,NAME_HMAC_KEY,NAME_ALGO = security.RC4_encrypt(name.encode('utf-8'))
        CIPHER_SURNAME,SURNAME_TAG,SURNAME_INIT_VALUE,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY,SURNAME_ALGO = security.RC4_encrypt(surname.encode('utf-8'))
        CIPHER_EMAIL,EMAIL_TAG,EMAIL_INIT_VALUE,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,EMAIL_ALGO = security.RC4_encrypt(email.encode('utf-8'))
        pw = password
        cursor.execute("""INSERT INTO USERS(CIPHER_NAME,NAME_TAG,NAME_ALGO_KEY,NAME_HMAC_KEY,NAME_ALGO,CIPHER_SURNAME,SURNAME_TAG,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY,SURNAME_ALGO,CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,EMAIL_ALGO,PASSWORD) 
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""" , (CIPHER_NAME,NAME_TAG,NAME_ALGO_KEY,NAME_HMAC_KEY,NAME_ALGO, CIPHER_SURNAME,SURNAME_TAG,SURNAME_ALGO_KEY,SURNAME_HMAC_KEY,SURNAME_ALGO, CIPHER_EMAIL,EMAIL_TAG,EMAIL_ALGO_KEY,EMAIL_HMAC_KEY,EMAIL_ALGO,pw))
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
