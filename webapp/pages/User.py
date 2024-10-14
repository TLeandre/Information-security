import streamlit as st
import db as db
import security
import pandas as pd 

## User not connected
if ('id' not in st.session_state) or (st.session_state.id == -1):
    #Log in form
    with st.form("Log in"):
        st.title("Log in")
        l_email = st.text_input("Email", key="l_email")
        l_password = st.text_input("Password", key="l_password", type="password")

        submitted = st.form_submit_button("Login")
        if submitted:
            id = db.connect(l_email, l_password)
            if id >= 0 :
                st.success("You are connected")
                st.session_state.id = id
            else:
                st.warning("Somethings goes wrong, double check your email / password")

    #Sign up form
    with st.form("Sign up"):
        st.title("Sign up")
        s_name = st.text_input("Name", key="s_name")
        s_surname = st.text_input("Surname", key="s_surname")
        s_email = st.text_input("Email", key="s_email")
        s_password = st.text_input("Password", key="s_password", type="password")

        submitted = st.form_submit_button("Sign in")
        if submitted:
            add = db.sign_in(s_name, s_surname, s_email, security.hash_password(s_password))
            if add == 0:
                st.success("Sign up completed")
            elif add == -1:
                st.warning("Email already use") 
## User connected            
else:
    st.title("User")

    infos = db.get_user(st.session_state.id)

    st.markdown(f"""### Name : {infos[0]}  
### Surname : {infos[1]}  
### email : {infos[2]}  
""")

    if st.button("Logout"):
        st.session_state.id = -1 
        st.success("Disconnection completed")
