import streamlit as st
import db as db

if ('id' not in st.session_state) or (st.session_state.id == -1):
    st.title("Login")
    l_email = st.text_input("Email", key="l_email")
    l_password = st.text_input("Password", key="l_password", type="password")
    if st.button("Login"):
        id = db.connect(l_email, l_password)
        if id >= 0 :
            st.success("You are connected")
            st.session_state.id = id
        else:
            st.warning("Somethings goes wrong, double check your email / password")


    st.title("Sign in ")
    s_name = st.text_input("Name", key="s_name")
    s_surname = st.text_input("Surname", key="s_surname")
    s_email = st.text_input("Email", key="s_email")
    s_password = st.text_input("Password", key="s_password", type="password")
    if st.button("Sign in"):
        add = db.sign_in(s_name, s_surname, s_email, s_password)
        if add == 0:
            st.success("Sign in completed")
        elif add == -1:
            st.warning("Email already use")
else:
    st.title("User")
    if st.button("Logout"):
        st.session_state.id = -1   
