import sqlite3
from sqlite3 import Error

def connect(email, password):
  try:
    con = sqlite3.connect('database.db', check_same_thread=False)
    cursor = con.cursor()
    cursor.execute("""SELECT PASSWORD, 
                        ID_USER FROM USERS 
                        WHERE EMAIL = '%s' """ % (str(email)) )
    pw = cursor.fetchall()
    if (pw[0][0] == password):
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
    
def insert_into_database(id, file_path_name, file_blob, tag, nonce,aes_key, hmac_key): 
  try:
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    sql = '''INSERT INTO FILES(ID_USER, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_NONCE, AES_KEY, HMAC_KEY)
             VALUES(?, ?, ?, ?, ?, ?, ?)'''
    cur.execute(sql, (id, file_path_name, file_blob, tag, nonce,aes_key, hmac_key))
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
  sql = """SELECT ID_FILES, FILE_NAME, CIPHER_FILE, FILE_TAG, FILE_NONCE, AES_KEY, HMAC_KEY 
           FROM FILES
           WHERE ID_USER = ?"""
  cur.execute(sql, (id,))
  files = cur.fetchall()
  return files


# con = sqlite3.connect("tutorial.db")
# cur = con.cursor()

# cur.execute("""CREATE TABLE IF NOT EXISTS uploads (
#   id integer PRIMARY KEY,
#   file_name text NOT NULL,
#   file_blob text NOT NULL,
#   file_tag text NOT NULL,
#   file_nonce text NOT NULL,
#   aes_key text NOT NULL,
#   hmac_key text NOT NULL
# );""")

# con.commit()
# con.close()



def convert_into_binary(file_path):
  with open(file_path, 'rb') as file:
    binary = file.read()
  return binary



def write_to_file(binary_data, file_name):
  with open(file_name, 'wb') as file:
    file.write(binary_data)
  print("[DATA] : The following file has been written to the project directory: ", file_name)

def read_blob_data(entry_id):
  try:
    conn = sqlite3.connect('tutorial.db')
    cur = conn.cursor()
    print("[INFO] : Connected to SQLite to read_blob_data")
    sql_fetch_blob_query = """SELECT * from uploads where id = ?"""
    cur.execute(sql_fetch_blob_query, (entry_id,))
    record = cur.fetchall()
    for row in record:
      converted_file_name = row[1]
      photo_binarycode  = row[2]
      # parse out the file name from converted_file_name
      # Windows developers should reverse "/" to "\" to match your file path names 
      last_slash_index = converted_file_name.rfind("\\") + 1 
      final_file_name = converted_file_name[last_slash_index:] 
      write_to_file(photo_binarycode, final_file_name)
      print("[DATA] : Image successfully stored on disk. Check the project directory. \n")
    cur.close()
  except sqlite3.Error as error:
    print("[INFO] : Failed to read blob data from sqlite table", error)
  finally:
    if conn:
        conn.close()


def main():
    conn = sqlite3.connect('tutorial.db')
    cur = conn.cursor()
    sql_fetch_blob_query = """SELECT id,file_name from uploads"""
    cur.execute(sql_fetch_blob_query)
    print(cur.fetchall())
    conn.commit()
    conn.close()
    # file_path_name = input("Enter full file path:\n") 
    # file_path_name = file_path_name.replace("\\", "\\\\")
    # file_blob = convert_into_binary(file_path_name)
    # print("[INFO] : the last 100 characters of blob = ", file_blob[:100])
    # last_updated_entry = insert_into_database(file_path_name, file_blob)
    # read_blob_data(last_updated_entry)
    
if __name__ == "__main__":
  main()