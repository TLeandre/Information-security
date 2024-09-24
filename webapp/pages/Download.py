import streamlit as st
import pandas as pd
import sqlite3
from sqlite3 import Error
import db as db
import os

from streamlit_pdf_viewer import pdf_viewer
import io


from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import sys

st.set_page_config(layout='wide')

with st.container():
    col1, col2 = st.columns([1,4], gap="large", vertical_alignment = "top")

    conn = sqlite3.connect('tutorial.db')
    cur = conn.cursor()
    sql_fetch_blob_query = """SELECT id,file_name,file_blob,file_tag, file_nonce, aes_key, hmac_key from uploads"""
    cur.execute(sql_fetch_blob_query)


    df = pd.DataFrame(cur.fetchall())
    with col1:
        st.dataframe(df[1], column_config={
            "1": "Nom du fichier"
        }
        ,width = 1000, hide_index=1)

        selected_item = st.selectbox("Choisissez un fichier :", df[1])

    # Récupérer l'index de l'élément sélectionné
    index = df[df[1] == selected_item].index[0]


    extension = os.path.splitext(selected_item)[1]
    # st.write(extension)
    # st.write(index)

    bytes = df[2].get(index)
    tag = df[3].get(index)
    nonce = df[4].get(index)
    aes_key = df[5].get(index)
    hmac_key = df[6].get(index)
    try:
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        tag = hmac.update(nonce + bytes).verify(tag)
    except ValueError:
        st.write("The message was modified!")
        sys.exit(1)

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    message = cipher.decrypt(bytes)
    
    bytes = message
    

    with col2:
        st.download_button("Download the file",bytes,selected_item, use_container_width = 1)
        if extension == ".mp4":
            st.video(bytes)
        elif extension == ".mp3":
            st.audio(bytes)
        elif extension == ".png":
            st.image(bytes)
        elif extension == ".webp":
            st.image(bytes)    
        elif extension == ".pdf":
            pdf_viewer(input=bytes,
                        width=700)
        elif extension == ".XLS":
            st.write(bytes)
        elif extension == ".csv":
            with open(selected_item, 'wb') as file:
                file.write(bytes)
            data_text = io.StringIO(bytes.decode('utf-8')) 
            st.dataframe(pd.read_csv((data_text), delimiter=';'))
        else :
            st.write("Exention de fichier non traités")