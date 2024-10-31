import streamlit as st
import pandas as pd
import db as db
import os

from streamlit_pdf_viewer import pdf_viewer
import io
from docx import Document


from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import sys

import security

st.set_page_config(layout='wide')

if ('id' in st.session_state) and (st.session_state.id != -1):
    with st.container():
        col1, col2 = st.columns([1,4], gap="large", vertical_alignment = "top")
        
        #retrieve the document from the database 
        files = db.get_files(st.session_state.id)
        df = pd.DataFrame(files)

        #checking the number of documents
        if df.shape[0] <= 0:
            st.write("No documents have been uploaded yet, go to the upload page to secure your data ")
        else : 
            ## display all documents 
            with col1:
                st.dataframe(df[1], 
                             column_config={"1": "Nom du fichier"},
                             width = 1000, 
                             hide_index=1)
            
            with col2:
                selected_item = st.selectbox("Select a document :", df[1])

                # Récupérer l'index de l'élément sélectionné
                index = df[df[1] == selected_item].index[0]

                extension = os.path.splitext(selected_item)[1]

                ciphertext = df[2].get(index)
                tag = df[3].get(index)
                init_value = df[4].get(index)
                algo_key = df[5].get(index)
                hmac_key = df[6].get(index)
                algo = df[7].get(index)
                digital_signature = df[8].get(index)

                ## decryption 
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

                ## display selected document 
                if extension == ".mp4":
                    st.video(plaintext)
                elif extension == ".mp3":
                    st.audio(plaintext)
                elif extension == ".png":
                    st.image(plaintext)
                elif extension == ".webp":
                    st.image(plaintext)    
                elif extension == ".pdf":
                    st.title("Document Signature")
                    
                    private_key = db.get_private_key(st.session_state.id)
                    public_key = db.get_public_key(st.session_state.id)
                    
                    if st.button("Document Signature",use_container_width=1):
                        digital_signature_encrypt = security.digital_signature_encrypt(ciphertext=plaintext,private_key=private_key)
                        db.insert_digital_signature(id_file= df[0].get(index),digital_signature=digital_signature_encrypt)
                    
                    if st.button("Document Verifying",use_container_width=1):
                        a = 0
                        digital_signature_decrypt = security.digital_signature_decrypt(cipher_digital_signature=digital_signature,public_key=public_key)
                        
                        if(digital_signature_decrypt == bytes.fromhex(security.hash_signature(plaintext))):
                            st.write("The document is verrified")
                        else:
                            st.write("The document is not verrified")
                    
                    pdf_viewer(input=plaintext,
                                width=700)
                elif extension == ".XLS":
                    st.write(plaintext)
                elif extension == ".csv":
                    with open(selected_item, 'wb') as file:
                        file.write(plaintext)
                    data_text = io.StringIO(plaintext.decode('utf-8')) 
                    st.dataframe(pd.read_csv((data_text), delimiter=';'))
                elif extension == ".docx":
                    docx_buffer = io.BytesIO(plaintext)
                    # Lire le document docx depuis le buffer
                    document = Document(docx_buffer)
                    # Afficher le contenu du document
                    for para in document.paragraphs:
                        st.write(para.text)
                else :
                    st.markdown("""File extension not supported :  
                                - Preview not available  
                                - Downloaded file does not match the original  
                                - Decryption doesn't work properly
                                """)
else : 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")