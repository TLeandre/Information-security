import sqlite3
from sqlite3 import Error
import security

def connect(email: str, password: str):
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
    
def sign_in(name, surname, email, password):
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
    
def insert_into_database(id, file_path_name, ciphertext, tag, init_value, algo_key, hmac_key): 
  try:
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    sql = '''INSERT INTO FILES(ID_USER, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_INIT_VALUE, ALGO_KEY, HMAC_KEY)
             VALUES(?, ?, ?, ?, ?, ?, ?)'''
    cur.execute(sql, (id, file_path_name, ciphertext, tag, init_value, algo_key, hmac_key))
    con.commit()
  except Error as e:
    print(e)  
  finally: 
    if con:
      con.close()
    else:
      error = "Oh shucks, something is wrong here."

def get_files(id):
  con = sqlite3.connect('database.db')
  cur = con.cursor()
  sql = """SELECT ID_FILES, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_INIT_VALUE, ALGO_KEY, HMAC_KEY 
           FROM FILES
           WHERE ID_USER = ?"""
  cur.execute(sql, (id,))
  files = cur.fetchall()
  return files
