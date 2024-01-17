from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import base64

import sqlite3
import os
from getpass import getpass

from modules.pseudo_frontend import success, error, warning, get_options, clear_terminal, user_message, contact_message

#---------------------------------------------- connect to database ----------------------------------------------#

def connect_auth_db():
    module_path = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_path, '..', 'general_data', 'auth.db')
    return sqlite3.connect(db_path)

def connect_user_db(id):
    module_path = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_path, '..', 'user_data', f'{id}.db')
    return sqlite3.connect(db_path)

def connect_main_db():
    module_path = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_path, '..', 'general_data', 'main.db')
    return sqlite3.connect(db_path)

#---------------------------------------------- commonly used functions ----------------------------------------------#

# Get user's contacts or requests
def get_people(user_id, accepted=1):
    
    with connect_user_db(user_id) as conn_user:
        cursor = conn_user.cursor()
        cursor.execute('SELECT id, username, public_key FROM contacts WHERE accepted = ?', (accepted,))
        return cursor.fetchall()
    
#---------------------------------------------- init functions ----------------------------------------------#

# Get data from main database and insert it into user's database
def refresh_db(user_id, private_key):
    
    with connect_main_db() as conn_main, connect_user_db(user_id) as conn_user:
    
        cursor_main = conn_main.cursor()
        cursor_user = conn_user.cursor()

        # Fetch and delete accepted requests
        cursor_main.execute('SELECT id_recieve FROM requests WHERE id_send = ? AND accepted = 1', (user_id,))
        new_accepted_id = [id_tuple[0] for id_tuple in cursor_main.fetchall()]
        cursor_main.execute('DELETE FROM requests WHERE accepted = 1 AND id_send = ? ', (user_id,))

        # Fetch and delete denied requests
        cursor_main.execute('SELECT id_recieve FROM requests WHERE id_send = ? AND accepted = -1', (user_id,))
        new_denied_id = [id_tuple[0] for id_tuple in cursor_main.fetchall()]
        cursor_main.execute('DELETE FROM requests WHERE accepted = -1 AND id_send = ? ', (user_id,))

        # Fetch new requests
        cursor_main.execute('SELECT id_send FROM requests WHERE id_recieve = ? AND accepted = 0', (user_id,))
        new_request_ids = [id_tuple[0] for id_tuple in cursor_main.fetchall()]
        new_requests = []
        for new_id in new_request_ids:
            cursor_main.execute('SELECT id, username, public_key FROM public_keys WHERE id = ?', (new_id,))
            new_requests.append(cursor_main.fetchone())

        # Insert new requests into user's contacts
        for new_request in new_requests:
            cursor_user.execute('SELECT id FROM contacts WHERE id = ?', (new_request[0],))
            existing_contact = cursor_user.fetchone()
            if existing_contact is None:
                cursor_user.execute('INSERT INTO contacts (id, username, public_key, accepted) VALUES (?, ?, ?, 2)', new_request)

        # Update accepted contacts and create chat tables
        for id in new_accepted_id:
            cursor_user.execute('UPDATE contacts SET accepted = 1 WHERE id = ?', (id,))
            cursor_user.execute(f'CREATE TABLE chat_with_{id} (text TEXT, sent INTEGER)')

        # Delete denied contacts
        for id in new_denied_id:
            cursor_user.execute('DELETE FROM contacts WHERE id = ?', (id,))

        # Fetch and delete messages
        cursor_main.execute('SELECT id_send, message FROM messages WHERE id_recieve = ?', (user_id,))
        new_messages = cursor_main.fetchall()
        cursor_main.execute('DELETE FROM messages WHERE id_recieve = ?', (user_id,))

        # Insert new messages into chat tables
        for new_message in new_messages:
            id_send = new_message[0]
            message = decrypt_message(new_message[1], private_key)
            cursor_user.execute(F'INSERT INTO chat_with_{id_send} (sent, text) VALUES (? , ?)', (0, message,))

        # Commit changes to both databases
        conn_main.commit()
        conn_user.commit()

# Get the user's username        
def get_username(id):
        
        with connect_user_db(id) as conn_user:
            cursor = conn_user.cursor()
            cursor.execute('SELECT username FROM user_data')
            return cursor.fetchone()[0]
        
# Get the user's private and public keys
def get_keys(id):
            
            with connect_user_db(id) as conn_user:
                cursor = conn_user.cursor()
                cursor.execute('SELECT private_key, public_key FROM user_data')
                return cursor.fetchone() 
     
#---------------------------------------------- request functions ----------------------------------------------#  

# Ask for a username and returns the data of the user with that username
def get_request_data():
        
        while True:
            try:
                request_username = warning('Username: ', type='input')
                
                with connect_main_db() as conn_main:
                    cursor = conn_main.cursor()
                    cursor.execute('SELECT id, username, public_key FROM public_keys WHERE username = ?', (request_username,))
                    request_data = cursor.fetchone()
                    
                    if request_data:
                        return request_data
                    else:
                        clear_terminal()
                        error('Username not found')
            except KeyboardInterrupt:
                return False

# Insert a request into the database       
def send_request_to(request_data, user_id):
    request_id = request_data[0]
    request_username = request_data[1]
    request_public_key = request_data[2]

    with connect_user_db(user_id) as conn_user, connect_main_db() as conn_main:
        cursor_user = conn_user.cursor()
        cursor_main = conn_main.cursor()

        # Check if contact already exists or request already sent/received
        cursor_user.execute('SELECT accepted FROM contacts WHERE id = ?', (request_id,))
        contact_status = cursor_user.fetchone()

        if contact_status is not None:
            clear_terminal()
            if contact_status[0] == 1:
                error('You already have this contact')
            elif contact_status[0] == 0:
                error('You already sent a request to this contact')
            elif contact_status[0] == 2:
                error('This contact already sent you a request')
        else:
            # Insert new contact and request
            cursor_user.execute('INSERT INTO contacts (id, username, public_key, accepted) VALUES (?, ?, ?, 0)', (request_id, request_username, request_public_key))
            cursor_main.execute('INSERT INTO requests (id_send, id_recieve, accepted) VALUES (?, ?, 0)', (user_id, request_id))
            clear_terminal()
            success(f'Request sent to {request_username}')

        # Commit changes to both databases
        conn_user.commit()
        conn_main.commit()
 
# Accept or deny a request                   
def interact_request(request_data, user_id):
    request_id, request_username, _ = request_data

    while True:
        ans = warning(f'Accept request from {request_username}? (y/n): ', type='input').lower().strip()
        if ans in ['y', 'n']:
            break
        print('Invalid answer')

    with connect_user_db(user_id) as conn_user, connect_main_db() as conn_main:
        cursor_user = conn_user.cursor()
        cursor_main = conn_main.cursor()

        if ans == 'y':
            # Update accepted and create chat tables
            cursor_user.execute('UPDATE contacts SET accepted = 1 WHERE id = ?', (request_id,))
            cursor_main.execute('UPDATE requests SET accepted = 1 WHERE id_send = ? AND id_recieve = ?', (request_id, user_id))
            cursor_user.execute(f'CREATE TABLE chat_with_{request_id} (text TEXT, sent INTEGER)')
            conn_user.commit()
            clear_terminal()
            return f'Request from {request_username} accepted'

        else:
            # Delete request from userr's database and update accepted at main database
            cursor_user.execute('DELETE FROM contacts WHERE id = ?', (request_id,))
            cursor_main.execute('UPDATE requests SET accepted = -1 WHERE id_send = ? AND id_recieve = ?', (request_id, user_id))
            clear_terminal()
            return f'Request from {request_username} denied'
        
#---------------------------------------------- chat functions ----------------------------------------------#
        
# Decrypt a message
def decrypt_message(encrypted_message, private_key_pem):
    
    # Convert the private key PEM to a private key object
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    # Decode the base64 encoded message
    encrypted_message_bytes = base64.b64decode(encrypted_message)

    # Decrypt the message
    decrypted_message = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode('utf-8')

 # Encrypt a message
def encrypt_message(message, public_key_pem):
    
    # Convert the public key PEM to a public key object
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )

    # Encrypt the message
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encode the encrypted message to base64
    encrypted_message_str = base64.b64encode(encrypted_message).decode('utf-8')

    return encrypted_message_str

# Print all the messages from a chat
def print_messages(id_user, user_name, id_chat, chat_name):

    user_name = get_username(id_user)

    
    with connect_user_db(id_user) as conn_main:
        cursor = conn_main.cursor()
        cursor.execute(F'SELECT text, sent FROM chat_with_{id_chat}')
        messages = cursor.fetchall()
        
    for message in messages:
        if message[1] == 1:
            user_message(user_name, message[0])
        else:
            contact_message(chat_name, message[0])
 
# Insert a message into the database           
def send_message(id_user, id_chat):
    
    with connect_main_db() as conn_main, connect_user_db(id_user) as conn_user:
        cursor_main = conn_main.cursor()
        cursor_user = conn_user.cursor()

        cursor_main.execute('SELECT public_key FROM public_keys WHERE id = ?', (id_chat,))
        public_key_pem = cursor_main.fetchone()[0]

        new_message = warning('Message: ', type='input')
        print('\033[F\033[K', end='')

        if new_message:
            encrypted_message = encrypt_message(new_message, public_key_pem)

            cursor_user.execute(F'INSERT INTO chat_with_{id_chat} (text, sent) VALUES (?, 1)', (new_message,))
            conn_user.commit()

            cursor_main.execute('INSERT INTO messages (id_send, message, id_recieve) VALUES (?, ?, ?)', (id_user, encrypted_message, id_chat))
            conn_main.commit()
            
            user_message(get_username(id_user), new_message)
        
#----------------------------------------------- class User -----------------------------------------------#

class User:
    
    # Initialize the user
    def __init__(self, id):
                
        self.id = id
        self.username = get_username(id)
        self.private_key, self.public_key = get_keys(id)
        
        refresh_db(self.id, self.private_key)
    
    # View the user's contacts
    def view_contacts(self):  
        
        success('Contacts')   
        
        contacts_list = get_people(self.id, accepted=1)
        options_list = [[i+1, contact[1]] for i, contact in enumerate(contacts_list)]
        if not options_list:
            clear_terminal()
            error('You have no contacts')
            getpass('')
        else:
            try:
                get_options(options_list, title='Contacts', text='' )
            except KeyboardInterrupt:
                pass
    
    # Send a request to a user        
    def send_request(self):
        
        success('Send a request')
        
        while True:

            request_data = get_request_data()
            if request_data:
                send_request_to(request_data, self.id)
            else:
                break
    
    # Manage the user's requests        
    def manage_requests(self):

        title_requests = 'Requests'

        contacts_list = get_people(self.id, accepted=2)
        options_list = [[i+1, contact[1]] for i, contact in enumerate(contacts_list)]
        if not options_list:
            clear_terminal()
            error('You have no requests')
            getpass('')
        else:
            try:
                request_chonsen = get_options(options_list, title=title_requests, text='Select a request to interact: ', error_msg='You Have no requests' )
                title_requests = interact_request(contacts_list[request_chonsen-1], self.id)
            except KeyboardInterrupt:
                pass
    
    # Chat with a user        
    def chat(self, contact):
        
        contact_id = contact[0]
        contact_username = contact[1]
        contact_public_key = contact[2]
        
        clear_terminal()
        success(f'Chatting with {contact[1]}')
        print_messages(self.id, self.username, contact_id, contact_username)
        while True:
            try:
                send_message(self.id, contact_id)
            except KeyboardInterrupt:
                break
                
            
        
#----------------------------------------------- options from user_menu -----------------------------------------------#   

# Choose a contact to chat with
def chat_option(user):
        
    contacts_list = get_people(user.id, accepted=1)
    options_list = [[i+1, contact[1]] for i, contact in enumerate(contacts_list)]
       
    if not options_list:
        clear_terminal()
        error('You have no contacts')
        getpass('')        
    else:    
        while True:
            try:
                option = get_options(options_list, title='Contacts', text='Select a contact: ', error_msg='Invalid contact')
                user.chat(contacts_list[option-1])
            except KeyboardInterrupt:
                break
 
 # Choose between viewing contacts, sending a request or managing requests           
def contact_option(user):
    
    options_list = [[1, 'View contacts'],
                    [2, 'Send request'],
                    [3, 'Manage Requests'],
    ]
    
    while True:
        try:
            option = get_options(options_list, title='Contacts', text='Select an option: ', print_success=False)
            
            if option == 1:
                user.view_contacts()
            elif option == 2:
                user.send_request()
            elif option == 3:
                user.manage_requests()
            elif option == 0:
                break
        except KeyboardInterrupt:
            break        
        
#------------------------------------------------------ user_menu ------------------------------------------------------------#

# Displays the user menu
def user_menu(id):
    
    user = User(id)
    option_list = [[1, 'Chat'],
                   [2, 'Contacts'],
                   [3, 'Logout'],
                   
                   [0, 'Exit']]
    
    while True:
        try:
            option = get_options(option_list, title=f'Wellcome {user.username}')
            
            if option == 1:
                chat_option(user)
            elif option == 2:
                contact_option(user)
            elif option == 3:
                break
            elif option == 0:
                success('Goodbye!')
                os._exit(0)
        except KeyboardInterrupt:
            pass

        