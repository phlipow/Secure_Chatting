import hashlib
import binascii
import secrets
import os
import sqlite3

from getpass import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules.pseudo_frontend import success, error, get_options, clear_terminal, warning

#-------------------------------------------------------------------- connect to database --------------------------------------------------------------------#

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

#------------------------------------------------------------------ communly used functions ------------------------------------------------------------------#

# Get the user's ID
def get_id(username):
    
    with connect_auth_db() as conn_auth:
        cursor = conn_auth.cursor()
        cursor.execute('SELECT id FROM auth WHERE username = ?', (username,))
        user_id = cursor.fetchone()
        
        if user_id:
            user_id = user_id[0]
            
        return user_id
    
# Check if a username exists
def check_username(username):
            
    with connect_auth_db() as conn_auth:
        cursor = conn_auth.cursor()
        cursor.execute('SELECT * FROM auth WHERE username = ?', (username,))
        result = cursor.fetchone()

    return result is not None

# Hash the password
def hash_password(password, salt):
    
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return binascii.hexlify(dk).decode()

#-------------------------------------------------------------------- register functions --------------------------------------------------------------------#

# Check if the username is valid for register
def register_username():
    
    while True:
        username = warning('Username: ', type='input')
        if not check_username(username):
            return username
        else:
            error('Username already exists')

# Check if a password is valid for register
def register_password():
    
    while True:
        
        password = getpass('\033[94mPassword: \033[0m')
        
        it_is = True
        
        # Check password requirements
        if not (8 <= len(password) <= 20):
            it_is = False
            error('Password must contain between 8 and 20 characters')

        if not any(character.isupper() for character in password):
            it_is = False
            error('Password must contain at least one uppercase character')

        if not any(character.islower() for character in password):
            it_is = False
            error('Password must contain at least one lowercase character')

        if not any(character.isdigit() for character in password):
            it_is = False
            error('Password must contain at least one digit')

        if not any(not character.isalnum() for character in password):
            it_is = False
            error('Password must contain at least one special character')
            
        # Check if the password is the same as the confirmation
        if it_is:
            if password != getpass('\033[94mConfirm Password: \033[0m'):
                error('Passwords do not match')
                it_is = False
        if it_is:
            return password

# Create user key pair
def key_pair():

    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Convert to bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Convert to string
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key_pem, public_key_pem

# Insert a new user into the database
def create_user(username, salt, hashed):
    
    # Insert on auth database
    with connect_auth_db() as conn_auth:
        cursor = conn_auth.cursor()
        cursor.execute('INSERT INTO auth (username, password, salt) VALUES (?, ?, ?)', (username, hashed, salt))
        conn_auth.commit()
        user_id = cursor.lastrowid

    private_key, public_key = key_pair()
    conn_user = connect_user_db(user_id)
    
    # Insert on user database
    with conn_user:
        conn_user.execute('CREATE TABLE IF NOT EXISTS user_data (id INTEGER PRIMARY KEY, username TEXT, private_key TEXT, public_key TEXT)')
        conn_user.execute('INSERT INTO user_data (id, username, private_key, public_key) VALUES (?, ?, ?, ?)', (user_id, username, private_key, public_key))

        conn_user.execute('CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, username TEXT, public_key TEXT, accepted INTEGER)')

    # Insert to main database
    with connect_main_db() as conn_main:
        conn_main.execute('INSERT INTO public_keys (id, username, public_key) VALUES (?, ?, ?)', (user_id, username, public_key))

    return user_id

#--------------------------------------------------------------------- log in functions ---------------------------------------------------------------------#

# Check if a username is valid for log in:
def login_username():
    
    while True:
        username = warning('Username: ', type='input')
        if check_username(username):
            return username
        else:
            error('Username does not exist')
            
# Check if a password is valid for log in
def login_password(id):
    
    attempt = 1
    while attempt <= 10:
        password = getpass('\033[94mPassword: \033[0m')
    
        with connect_auth_db() as conn_auth:
            cursor = conn_auth.cursor()
            cursor.execute('SELECT salt, password FROM auth WHERE id = ?', (id,))
            salt, hashed = cursor.fetchone()
        
        if hash_password(password, salt) == hashed:
            return password
        else:
            error(f'Incorrect password\nAttempt {attempt}/10')
            attempt += 1
    error('Attempt limit reached')
    os._exit(0)

#------------------------------------------------------------------------ class auth ------------------------------------------------------------------------#

class Auth:

    # Register a new user
    def register(self):
            
        username = register_username()
        password = register_password()       
        salt = secrets.token_hex(16)
        hashed = hash_password(password, salt)

        create_user(username, salt, hashed)
        
        clear_terminal()
        success('Registered successful')
        warning('Enter to continue', type='message')
        getpass('')
        

    # Log a user in
    def login(self):
        
        username = login_username()
        id = get_id(username)
        password = login_password(id)
        
        clear_terminal()
        success('Logged in successful')
        warning('Enter to continue', type='message')
        getpass('')
        
        return id
    
#-------------------------------------------------------------------------- auth menu --------------------------------------------------------------------------#

# Displays the authentification menu
def auth_menu():
    
    user = Auth()
    option_list = [[1, 'Login'],
                   [2, 'Register'],
                   [0, 'Exit']]
    
    while True:
        try:
            option = get_options(option_list, title='Wellcome', warn='You can always go back by pressing Ctrl + C')
            
            if option == 1:
                return user.login()
            elif option == 2:
                user.register()
            elif option == 0:
                success('Goodbye!')
                os._exit(0)
        except KeyboardInterrupt:
            pass
