from modules.auth_menu import auth_menu
from modules.user_menu import user_menu
from modules.installation import setup_databases

# Create the databases and tables if they don't exist
setup_databases()

while True:
    
    # Login or register the user
    id = auth_menu()
    
    # Show the user menu
    user_menu(id)