import streamlit as st
import db as db
import security
import os

from streamlit_pdf_viewer import pdf_viewer
import io
from docx import Document
import pandas as pd

from streamlit_pdf_viewer import pdf_viewer

st.set_page_config(layout='wide')

if ('id' in st.session_state) and (st.session_state.id != -1):
    shared_documents = db.get_shared_documents(st.session_state.id)

    user_documents = {}
    for email, file_name, cipher_file, file_tag, file_init_value, algo_key, hmac_key, algo in shared_documents:
        if email not in user_documents:
            user_documents[email] = []
        # Ajouter toutes les informations du fichier pour l'utilisateur
        user_documents[email].append({
            'file_name': file_name,
            'cipher_file': cipher_file,
            'file_tag': file_tag,
            'file_init_value': file_init_value,
            'algo_key': algo_key,
            'hmac_key': hmac_key,
            'algo': algo
        })

    # Liste déroulante pour sélectionner un utilisateur
    col1, col2 = st.columns([3, 7])
    with col1:
        selected_user = st.selectbox("Select a user", list(user_documents.keys()))
    with col2:
        shared_key_encrypt = st.text_input("Enter your access code:", type="password")
        private_key = db.get_private_key(st.session_state.id)
        shared_key = security.decrypt_shared_key(shared_key_encrypt, private_key)


    # Afficher les documents associés à l'utilisateur sélectionné
    if selected_user and shared_key:
        # Récupérer la liste des fichiers associés à l'utilisateur sélectionné
        file_list = [doc['file_name'] for doc in user_documents[selected_user]]
        
        # Afficher une liste déroulante pour sélectionner un fichier
        selected_file = st.selectbox("Select a file", file_list)
        
        # Afficher les détails du fichier sélectionné
        if selected_file:
            st.write(f"Selected document : {selected_file}")
            for document in user_documents[selected_user]:
                if document['file_name'] == selected_file:
                    extension = os.path.splitext(selected_file)[1]
                    algo_key_decrypt = security.aes_decrypt_key_for_shared(shared_key, document['algo_key'])
                    algo = document['algo']
                    ciphertext = document['cipher_file']
                    tag = document['file_tag']
                    init_value = document['file_init_value']
                    hmac_key = document['hmac_key']

                    if algo == "AES":
                        plaintext = security.AES_decrypt(ciphertext,
                                                        tag,
                                                        init_value,
                                                        algo_key_decrypt,
                                                        hmac_key)
                    elif algo == "DES":
                        plaintext = security.DES_decrypt(ciphertext,
                                                    tag,
                                                    init_value,
                                                    algo_key_decrypt,
                                                    hmac_key)
                    elif algo == "RC4":
                        plaintext = security.RC4_decrypt(ciphertext,
                                                    tag,
                                                    algo_key_decrypt,
                                                    hmac_key)
                    
                    if plaintext is None:
                        st.write("The message was modified!")
                    else : 
                        st.success(f"The file has been successfully decrypted using : {algo}")

                    st.download_button("Download the file", plaintext, selected_file, use_container_width = 1)

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
                        pdf_viewer(input=plaintext,
                                    width=700)
                    elif extension == ".XLS":
                        st.write(plaintext)
                    elif extension == ".csv":
                        with open(selected_file, 'wb') as file:
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
        st.write("Please select a user and the associated code")
else : 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")
