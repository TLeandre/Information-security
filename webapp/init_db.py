import sqlite3

def main():
    """
    Main function for initialise the database structure
    Table USERS contains all informations about Users
    Table FILES contains all files informations 
    """
    try:
        con = sqlite3.connect('database.db')
        cur = con.cursor()

        sql = '''CREATE TABLE IF NOT EXISTS USERS (
                        ID_USER INTEGER PRIMARY KEY AUTOINCREMENT,
                        NAME VARCHAR(10) NOT NULL,
                        SURNAME VARCHAR(10) NOT NULL,
                        EMAIL VARCHAR(10) NOT NULL,
                        PASSWORD VARCHAR(10) NOT NULL
                )'''
        cur.execute(sql)
        con.commit()

        sql = '''CREATE TABLE IF NOT EXISTS FILES (
                        ID_FILES INTEGER PRIMARY KEY AUTOINCREMENT,
                        ID_USER INTEGER,
                        FILE_NAME TEXT NOT NULL,
                        CIPHER_FILE TEXT NOT NULL,
                        FILE_TAG TEXT NOT NULL,
                        FILE_INIT_VALUE TEXT NOT NULL,
                        ALGO_KEY TEXT NOT NULL,
                        HMAC_KEY TEXT NOT NULL,
                        FOREIGN KEY(ID_USER) REFERENCES USERS(ID_USER)
                )'''
        cur.execute(sql)
        con.commit()

        con.close()
        print("Database created")
    except sqlite3.Error as error:
        print("[INFO] : Failed to create database : ", error)

    
if __name__ == "__main__":
    main()
    