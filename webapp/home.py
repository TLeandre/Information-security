import streamlit as st

st.set_page_config(
    page_title="Home page",
    layout="wide"
)

# Main title of the page
st.markdown("""
# Welcome to your Secure Data Storage Platform 🎈
            
This platform provides a secure environment for you to store and manage your personal data.   
All uploaded files are automatically encrypted, ensuring enhanced security for your information.  
You can explore the following features available on the site:
            
### 🔒 User
            
Log in to your account to access your files and other functionalities of the site.  
A secure login is the first step to using this tool.
            
### ⬆️ Upload
            
On this page, you can upload your files. Every file uploaded is encrypted before storage, guaranteeing its safety.
            
### ⬇️ Download
            
Access your previously uploaded files from this page.  
You can download them securely with decryption.
""")