import streamlit as st
import db as db
import security
import pandas as pd 

if ('id' not in st.session_state) or (st.session_state.id == -1):
    with st.form("Login"):
        st.title("Login")
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

    with st.form("Sign in"):
        st.title("Sign in")
        s_name = st.text_input("Name", key="s_name")
        s_surname = st.text_input("Surname", key="s_surname")
        s_email = st.text_input("Email", key="s_email")
        s_password = st.text_input("Password", key="s_password", type="password")

        submitted = st.form_submit_button("Sign in")
        if submitted:
            add = db.sign_in(s_name, s_surname, s_email, security.hash_password(s_password))
            if add == 0:
                st.success("Sign in completed")
            elif add == -1:
                st.warning("Email already use")
else:
    st.title("User")

    files = db.get_user(st.session_state.id)

    df = pd.DataFrame(files)

    st.dataframe(df)

    if st.button("Logout"):
        st.session_state.id = -1   
