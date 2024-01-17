import sqlite3
import os

def connect_auth_db():
    module_path = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_path, '..', 'general_data', 'auth.db')
    return sqlite3.connect(db_path)

def connect_main_db():
    module_path = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(module_path, '..', 'general_data', 'main.db')
    return sqlite3.connect(db_path)

# Create folders if they don't exist
def setup_folders():
    module_path = os.path.dirname(os.path.abspath(__file__))
    general_data_path = os.path.join(module_path, '..', 'general_data')
    user_data_path = os.path.join(module_path, '..', 'user_data')
    if not os.path.exists(general_data_path):
        os.makedirs(general_data_path)
    if not os.path.exists(user_data_path):
        os.makedirs(user_data_path)

# Create the databases and tables if they don't exist
def setup_databases():
    
    setup_folders()
    
    with connect_auth_db() as conn_auth:
        conn_auth.execute('CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY, username TEXT, password TEXT, salt TEXT)')
        
    with connect_main_db() as conn_main:
        conn_main.execute('CREATE TABLE IF NOT EXISTS public_keys (id INTEGER PRIMARY KEY, username TEXT, public_key TEXT)')
        conn_main.execute('CREATE TABLE IF NOT EXISTS messages (id_send INTEGER , message TEXT, id_recieve INTEGER)')
        conn_main.execute('CREATE TABLE IF NOT EXISTS requests (id_send INTEGER, id_recieve INTEGER, accepted INTEGER)')
            