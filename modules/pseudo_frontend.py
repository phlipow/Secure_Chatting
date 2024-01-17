import os
from getpass import getpass

# Green text
def success(text):
    print(f'\033[32m{text}\033[0m')

# Red text    
def error(text):
    print(f'\033[31m{text}\033[0m')

#Blue text    
def warning(text, i=0, type='message'):
    if type == 'message':
        print(f'\033[34m{text}\033[0m')
    elif type == 'input':
        x = input(f'\033[34m{text}\033[0m')
        return x
    elif type == 'option':
        print(f'\033[34m{i} - \033[0m{text}')
        
# Purple text with username
def user_message(name, msg):
    print('\033[35m' + name + ':' + '\033[0m', msg)
    
# Light purple text with username
def contact_message(name, msg):
    print('\033[95m' + name + ':' + '\033[0m', msg)

# Clear terminal
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')
    
# Show options and return the selected option
def get_options(options, title=False, first=True, print_success=True, error_msg='Invalid option',text='Select an option: ', warn=False):
    
    while True:
        
        clear_terminal()
        # If there was a warn before, print the message
        if warn:
            warning(warn, type='message')        
        # If there was a error before, print the error message
        if not first:
            error(error_msg)
            
        # If there is a title, print it
        if title:
            success(title)

        # Print all the options
        for option in options:
            warning(option[1], i=option[0], type='option')
            
        # Get the selected option 
        if not text:
            selected = getpass('')
        else:
            selected = warning(text, type='input')
         
        # If the selected option is valid, return it   
        try:
            selected = int(selected)
            if selected in [option[0] for option in options]:   
                instruction = [option[1] for option in options if option[0] == selected][0]
                clear_terminal()
                if print_success and selected != 0:
                    success(instruction)
                return selected
        
        except ValueError:
            pass
        
        # If the selected option is invalid, try again with the error message
        return get_options(options, title=False, first=False, error_msg=error_msg, text=text)