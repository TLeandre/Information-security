import streamlit as st
import pandas as pd
import sqlite3
from sqlite3 import Error
import db as db

# con = sqlite3.connect("tutorial.db")
# cur = con.cursor()

# cur.execute("""CREATE TABLE IF NOT EXISTS uploads (
#   id integer PRIMARY KEY,
#   file_name text NOT NULL,
#   file_blob text NOT NULL
# );""")

# con.commit()
# con.close()


uploaded_files = st.file_uploader(
    "Choose a file", accept_multiple_files=True
)
for uploaded_file in uploaded_files:
    bytes_data = uploaded_file.read()
    
    conn = sqlite3.connect('tutorial.db')
    cur = conn.cursor()
    last_updated_entry = db.insert_into_database(uploaded_file.name, bytes_data)
    conn.commit()
    conn.close()
    # insert_into_database(uploaded_file.name,bytes_data)
    st.write("filename:", uploaded_file.name)
    # st.write(bytes_data)

#Store user’s private data in a database
#Refer to GDPR (EU)/UU PDP for what are considered to be private data
#Store user’s ID card image
#Store user’s PDF/DOC/XLS files
#Store user’s video files
