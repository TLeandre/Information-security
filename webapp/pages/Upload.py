import streamlit as st

import db as db
import security

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

if ('id' in st.session_state) and (st.session_state.id != -1):
    
    uploaded_files = st.file_uploader(
        "Choose a file", accept_multiple_files=True
    )
    for uploaded_file in uploaded_files:
        bytes_data = uploaded_file.read()
        
        ciphertext, tag, nonce, aes_key, hmac_key = security.AES_encrypt(bytes_data)
        
        last_updated_entry = db.insert_into_database(st.session_state.id, 
                                                     uploaded_file.name, 
                                                     ciphertext,
                                                     tag,
                                                     nonce, 
                                                     aes_key, 
                                                     hmac_key)

        st.success("File upload :)")

else : 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")







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