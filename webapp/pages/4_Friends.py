import streamlit as st
import db as db

st.set_page_config(layout='wide')

if ('id' in st.session_state) and (st.session_state.id != -1):
    with st.container():
        st.title("My connections")

        # Récupérer les connexions en tant que demandeur
        requester_connections = db.get_confirmed_connections_as_requester(st.session_state.id)
        
        # Récupérer les connexions en tant que receveur
        receiver_connections = db.get_confirmed_connections_as_receiver(st.session_state.id)

        col1, col2 = st.columns([5, 5])

        # Afficher les connexions en tant que demandeur
        with col1:
            st.subheader("Connections where I can access data")
            if requester_connections:
                for connection_id, email in requester_connections:
                    st.write(f"**Email:** {email}")
                        
            else:
                st.write("No connection confirmed as a requester.")

        # Afficher les connexions en tant que receveur
        with col2:
            st.subheader("Connections that have access to my data")
            if receiver_connections:
                for connection_id, user_id, email in receiver_connections:
                    with st.form(key=f'form_receiver_{connection_id}'):
                        col1, col2 = st.columns([1, 1])

                        with col1:
                            st.write(f"**Email:** {email} {connection_id}")
                        with col2:
                            submit_button = st.form_submit_button("Update Files and change code")
                        if submit_button:
                            db.delete_shared_documents(st.session_state.id, user_id)
                            encrypted_shared_key = db.share_documents(st.session_state.id, db.get_requester_id(connection_id))
                            st.success(f"Security code : {encrypted_shared_key}")
            else:
                st.write("No confirmed connection as receiver.")

    st.divider()

    with st.container():
        connection_requests = db.get_connection_requests(st.session_state.id)
        st.title("Sharing requests received")

        if connection_requests:
            for connection_id, email in connection_requests:
                with st.form(f"request_form_{connection_id}"):
                    col1, col2, col3 = st.columns([3, 1, 1])
                    with col1:
                        st.write(f"Request for a share of : {email}")
                    with col2:
                        confirm_button = st.form_submit_button("Accept")
                    with col3:
                        deny_button = st.form_submit_button("Decline")
                    
                    if confirm_button:
                        # Logique pour accepter la demande
                        db.accept_connection_request(connection_id)
                        encrypted_shared_key = db.share_documents(st.session_state.id, db.get_requester_id(connection_id))
                        st.success(f"Your documents are shared with {email}, Security code : {encrypted_shared_key}")
                    elif deny_button:
                        # Logique pour refuser la demande
                        db.deny_connection_request(connection_id)
                        st.warning(f"Request to share {email} denied.")
        else:
            st.write("No sharing requests received.")

    st.divider()

    with st.container():
        st.title("All user")
        users = db.get_other_users_emails(st.session_state.id)

        for user_id, email in users:
            # Create a form for each email
            with st.form(key=f'form_{user_id}'):
                col1, col2 = st.columns([1, 1])

                with col1:
                    st.write(f"**Email:** {email}")
                with col2:
                # Button for document sharing request
                    submit_button = st.form_submit_button("Document sharing request")
                
                # If the form button is clicked
                if submit_button:
                    if db.connection_request_exists(st.session_state.id, user_id):
                        st.warning(f"You have already requested to share documents")
                    else:
                        db.add_connection_request(st.session_state.id, user_id)
                        st.success(f"Request sent")
else: 
    st.markdown("### Unfortunately, you're not logged in. Please log in to access our services ")