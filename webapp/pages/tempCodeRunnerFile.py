conn = sqlite3.connect('tutorial.db')
    cur = conn.cursor()
    cur.execute("""SELECT id,file_name from uploads""")
    print(cur.fetchall())