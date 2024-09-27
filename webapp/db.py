import sqlite3
from sqlite3 import Error
import security

### --- 
# User section
### --- 

def connect(email: str, password: str) -> list:
  try:
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()
    cursor.execute("""SELECT PASSWORD, 
                        ID_USER FROM USERS 
                        WHERE EMAIL = '%s' """ % (str(email)) )
    pw = cursor.fetchall()
    if (security.verify_password(pw[0][0], password)):
      return pw[0][1]
    else:
      return -1
  except:
    return -1
  finally:
    if con:
      con.close()
    else:
      error = "Oh shucks, something is wrong here."
    
def sign_in(name: str, surname: str, email: str, password: str) -> list:
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()
    cursor.execute("""SELECT EMAIL FROM USERS WHERE EMAIL = '%s' """ % (str(email)))
    mail = cursor.fetchall()

    if len(mail) <= 0:

        pw = password
        cursor.execute("""INSERT INTO USERS(NAME, SURNAME, EMAIL, PASSWORD) 
                        VALUES ('%s','%s','%s','%s')""" % (name, surname, email, pw))
        con.commit()
        return 0
    else :
        return -1 
    
def get_user(id: int) -> id:
  con = sqlite3.connect('database.db')
  cur = con.cursor()
  sql = """SELECT NAME, SURNAME, EMAIL
           FROM USERS
           WHERE ID_USER = ?"""
  cur.execute(sql, (id,))
  infos = cur.fetchall()

  return infos

### --- 
# Files section
### --- 
    
def insert_into_database(id: int, file_path_name: str, ciphertext: bytes, tag: bytes, init_value: bytes, algo_key: bytes, hmac_key: bytes, algo: bytes) -> None: 
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
  con = sqlite3.connect('database.db')
  cur = con.cursor()
  sql = """SELECT ID_FILES, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_INIT_VALUE, ALGO_KEY, HMAC_KEY, ALGO
           FROM FILES
           WHERE ID_USER = ?"""
  cur.execute(sql, (id,))
  files = cur.fetchall()

  return files
