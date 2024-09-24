import streamlit as st
import pandas as pd
import sqlite3
from sqlite3 import Error
import db as db

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

if ('id' in st.session_state) and (st.session_state.id != -1):
    
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
        
        last_updated_entry = db.insert_into_database(st.session_state.id, uploaded_file.name, ciphertext,tag,cipher.nonce, aes_key, hmac_key)

        st.success("File upload :)")







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