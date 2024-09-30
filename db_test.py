import os
import sqlite3
from sqlite3 import Error
import webapp.db as db

conn = sqlite3.connect('tutorial.db')
cur = conn.cursor()
sql_fetch_blob_query = """SELECT id,file_name from uploads"""
cur.execute(sql_fetch_blob_query)
print(cur.fetchall())
conn.commit()
conn.close()