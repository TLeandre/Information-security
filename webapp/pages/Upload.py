import streamlit as st

import db as db
import security

encryption_algorithms = [
    security.DES_encrypt, 
    security.AES_encrypt,
    security.RC4_encrypt,
]

if ('id' in st.session_state) and (st.session_state.id != -1):
    
    uploaded_file = st.file_uploader(
        "Choose a file", accept_multiple_files=False
    )
    if uploaded_file is not None:
        bytes_data = uploaded_file.read()
        
        for encrypt_function in encryption_algorithms:
            ciphertext, tag, init_value, algo_key, hmac_key, algo = encrypt_function(bytes_data)
            file_name = uploaded_file.name[:uploaded_file.name.rfind(".")-1] + "_" + algo + "_" + uploaded_file.name[uploaded_file.name.rfind("."):]
            
            last_updated_entry = db.insert_into_database(st.session_state.id, 
                                                        file_name, 
                                                        ciphertext,
                                                        tag,
                                                        init_value, 
                                                        algo_key, 
                                                        hmac_key,
                                                        algo)

        st.success("File uploaded")

else : 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")
