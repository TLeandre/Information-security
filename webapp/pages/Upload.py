import streamlit as st

import db as db
import security

if ('id' in st.session_state) and (st.session_state.id != -1):
    
    uploaded_file = st.file_uploader(
        "Choose a file", accept_multiple_files=False
    )
    if uploaded_file is not None:
        bytes_data = uploaded_file.read()
        
        ciphertext, tag, init_value, algo_key, hmac_key = security.DES_encrypt(bytes_data)
        
        last_updated_entry = db.insert_into_database(st.session_state.id, 
                                                     uploaded_file.name, 
                                                     ciphertext,
                                                     tag,
                                                     init_value, 
                                                     algo_key, 
                                                     hmac_key)

        st.success("File upload :)")

else : 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")
