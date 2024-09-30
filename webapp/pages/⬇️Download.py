import streamlit as st
import pandas as pd
import db as db
import os

from streamlit_pdf_viewer import pdf_viewer
import io


from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import sys

import security

st.set_page_config(layout='wide')

if ('id' in st.session_state) and (st.session_state.id != -1):
    with st.container():
        col1, col2 = st.columns([1,4], gap="large", vertical_alignment = "top")

        files = db.get_files(st.session_state.id)

        df = pd.DataFrame(files)

        #verification du nombre de document
        if df.shape[0] <= 0:
            st.write("No documents have been uploaded yet, go to the upload page to secure your data ")
        else : 
            with col1:
                st.dataframe(df[1], 
                             column_config={"1": "Nom du fichier"},
                             width = 1000, 
                             hide_index=1)
            
            with col2:
                selected_item = st.selectbox("Choisissez un fichier :", df[1])

                # Récupérer l'index de l'élément sélectionné
                index = df[df[1] == selected_item].index[0]

                extension = os.path.splitext(selected_item)[1]

                ciphertext = df[2].get(index)
                tag = df[3].get(index)
                init_value = df[4].get(index)
                algo_key = df[5].get(index)
                hmac_key = df[6].get(index)
                algo = df[7].get(index)

                if algo == "AES":
                    plaintext = security.AES_decrypt(ciphertext,
                                                    tag,
                                                    init_value,
                                                    algo_key,
                                                    hmac_key)
                elif algo == "DES":
                    plaintext = security.DES_decrypt(ciphertext,
                                                tag,
                                                init_value,
                                                algo_key,
                                                hmac_key)
                elif algo == "RC4":
                    plaintext = security.RC4_decrypt(ciphertext,
                                                tag,
                                                algo_key,
                                                hmac_key)
                
                if plaintext is None:
                    st.write("The message was modified!")
                    sys.exit(1)
                else : 
                    st.success(f"The file has been successfully decrypted using : {algo}")

                st.download_button("Download the file", plaintext, selected_item, use_container_width = 1)
                if extension == ".mp4":
                    st.video(plaintext)
                elif extension == ".mp3":
                    st.audio(plaintext)
                elif extension == ".png":
                    st.image(plaintext)
                elif extension == ".webp":
                    st.image(plaintext)    
                elif extension == ".pdf":
                    pdf_viewer(input=plaintext,
                                width=700)
                elif extension == ".XLS":
                    st.write(plaintext)
                elif extension == ".csv":
                    with open(selected_item, 'wb') as file:
                        file.write(plaintext)
                    data_text = io.StringIO(plaintext.decode('utf-8')) 
                    st.dataframe(pd.read_csv((data_text), delimiter=';'))
                else :
                    st.write("Exention de fichier non traités")
else : 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")