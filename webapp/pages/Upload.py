import streamlit as st
import pandas as pd
import sqlite3
from sqlite3 import Error
import db as db

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

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


uploaded_files = st.file_uploader(
    "Choose a file", accept_multiple_files=True
)
for uploaded_file in uploaded_files:
    bytes_data = uploaded_file.read()
    
    aes_key = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(bytes_data)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()
    
    conn = sqlite3.connect('tutorial.db')
    cur = conn.cursor()
    last_updated_entry = db.insert_into_database(uploaded_file.name, ciphertext,tag,cipher.nonce, aes_key, hmac_key)
    conn.commit()
    conn.close()
    st.write("Fichier upload :)")

#Store user’s private data in a database
#Refer to GDPR (EU)/UU PDP for what are considered to be private data
#Store user’s ID card image
#Store user’s PDF/DOC/XLS files
#Store user’s video files


# All stored data must be encrypted with all of these algorithms:
# AES
# RC4
# DES

# You need to use one of the non-ECB operation modes for the block cipher (i.e., CBC, CFB, OFB, CTR)


