import os
import sqlite3
from sqlite3 import Error

# con = sqlite3.connect("tutorial.db")
# cur = con.cursor()

# cur.execute("""CREATE TABLE IF NOT EXISTS uploads (
#   id integer PRIMARY KEY,
#   file_name text NOT NULL,
#   file_blob text NOT NULL
# );""")

# # # cur.execute("SELECT * FROM movie")
# # # print(cur.fetchall())

# con.commit()
# con.close()



def convert_into_binary(file_path):
  with open(file_path, 'rb') as file:
    binary = file.read()
  return binary
    
def insert_into_database(file_path_name, file_blob, tag, nonce,aes_key, hmac_key): 
  try:
    conn = sqlite3.connect('tutorial.db')
    print("[INFO] : Successful connection!")
    cur = conn.cursor()
    sql_insert_file_query = '''INSERT INTO uploads(file_name, file_blob, file_tag, file_nonce,aes_key, hmac_key)
      VALUES(?, ?, ?, ?, ?, ?)'''
    cur = conn.cursor()
    cur.execute(sql_insert_file_query, (file_path_name, file_blob, tag, nonce,aes_key, hmac_key, ))
    conn.commit()
    print("[INFO] : The blob for ", file_path_name, " is in the database.") 
    #last_updated_entry = cur.lastrowid
    #return last_updated_entry
  except Error as e:
    print(e)  
  finally:
    if conn:
      conn.close()
    else:
      error = "Oh shucks, something is wrong here."



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