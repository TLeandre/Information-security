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
                        
                        CIPHER_NAME TEXT NOT NULL,
                        NAME_TAG TEXT NOT NULL,
                        NAME_ALGO_KEY TEXT NOT NULL,
                        NAME_HMAC_KEY TEXT NOT NULL,
                        NAME_ALGO TEXT NOT NULL,
                        
                        CIPHER_SURNAME TEXT NOT NULL,
                        SURNAME_TAG TEXT NOT NULL,
                        SURNAME_ALGO_KEY TEXT NOT NULL,
                        SURNAME_HMAC_KEY TEXT NOT NULL,
                        SURNAME_ALGO TEXT NOT NULL,
                        
                        CIPHER_EMAIL TEXT NOT NULL,
                        EMAIL_TAG TEXT NOT NULL,
                        EMAIL_ALGO_KEY TEXT NOT NULL,
                        EMAIL_HMAC_KEY TEXT NOT NULL,
                        EMAIL_ALGO TEXT NOT NULL,

                        PASSWORD VARCHAR(10) NOT NULL,

                        PUBLIC_KEY TEXT,
                        PRIVATE_KEY TEXT,
                        SHARED_KEY TEXT
                )'''
        cur.execute(sql)
        con.commit()

        sql = '''CREATE TABLE IF NOT EXISTS FILES (
                        ID_FILES INTEGER PRIMARY KEY AUTOINCREMENT,
                        ID_USER INTEGER,
                        FILE_NAME TEXT NOT NULL,
                        CIPHER_FILE TEXT NOT NULL,
                        FILE_TAG TEXT NOT NULL,
                        FILE_INIT_VALUE TEXT,
                        ALGO_KEY TEXT NOT NULL,
                        HMAC_KEY TEXT NOT NULL,
                        ALGO TEXT NOT NULL,
                        SIGNATURE TEXT,
                        FOREIGN KEY(ID_USER) REFERENCES USERS(ID_USER)
                )'''
        cur.execute(sql)
        con.commit()

        sql = '''CREATE TABLE IF NOT EXISTS CONNECTIONS (
                        ID_CONNECTION INTEGER PRIMARY KEY AUTOINCREMENT,
                        ID_REQUESTER INTEGER NOT NULL,
                        ID_RECEIVER INTEGER NOT NULL,
                        IS_CONFIRMED INTEGER DEFAULT 0, -- 0: Non confirmé, 1: Confirmé
                        FOREIGN KEY(ID_REQUESTER) REFERENCES USERS(ID_USER),
                        FOREIGN KEY(ID_RECEIVER) REFERENCES USERS(ID_USER)
                )'''
        
        cur.execute(sql)
        con.commit()

        sql = '''CREATE TABLE IF NOT EXISTS SHARED_FILES (
                        ID_FILES INTEGER PRIMARY KEY AUTOINCREMENT,
                        ID_REQUESTER INTEGER NOT NULL,
                        ID_RECEIVER INTEGER NOT NULL,
                        FILE_NAME TEXT NOT NULL,
                        CIPHER_FILE TEXT NOT NULL,
                        FILE_TAG TEXT NOT NULL,
                        FILE_INIT_VALUE TEXT,
                        ALGO_KEY TEXT NOT NULL,
                        HMAC_KEY TEXT NOT NULL,
                        ALGO TEXT NOT NULL,
                        FOREIGN KEY(ID_REQUESTER) REFERENCES USERS(ID_USER),
                        FOREIGN KEY(ID_RECEIVER) REFERENCES USERS(ID_USER)
                )'''
        cur.execute(sql)
        con.commit()

        con.close()
        print("Database created")
    except sqlite3.Error as error:
        print("[INFO] : Failed to create database : ", error)

    
if __name__ == "__main__":
    main()
    