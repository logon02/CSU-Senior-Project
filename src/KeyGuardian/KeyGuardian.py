'''
This is KeyGuardian, an all-in-one software solution to password management
and creation.

This software is a password generator, checker, and manager of passwords which 
are stored securely in a local database.

Developed by: Logan Ferguson

'''

import base64
import sqlite3
import os
from tkinter import *
import tkinter
import customtkinter
from customtkinter import CTkImage
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from password_strength import PasswordPolicy
import string
import random
import math
import pyperclip
import bcrypt

def validate_login():
    username = username_entry.get()
    password = password_entry.get()

    try:
        connection = sqlite3.connect('description.db')
        cursor = connection.cursor()

        # Fetch user information based on the provided username
        cursor.execute("SELECT username, password FROM description WHERE username=?", (username,))
        result = cursor.fetchone()

        if result:
            db_username, db_password = result

            # Compare the username and password hash for authentication
            if username == db_username and bcrypt.checkpw(password.encode('utf-8'), db_password):
                # Decryption
                fetch_key = "SELECT password FROM description WHERE username = 'Key'"
                cursor.execute(fetch_key)
                result = cursor.fetchone()

                key = result[0]

                fernet = Fernet(key)

                with open('KeyGuardian.db', 'rb') as encrypted_database:
                    enc_data = encrypted_database.read()

                decrypted_data = fernet.decrypt(enc_data)

                # Write the decrypted data to a temporary file
                with open('KeyGuardian_temp.db', 'wb') as decrypted:
                    decrypted.write(decrypted_data)

                # Clear the entry fields
                username_entry.delete(0, END)
                password_entry.delete(0, END)

                # Hide the login frame
                login_frame.grid_forget()

                # Show the main frame
                main_frame.grid(row=0, column=0, padx=10, pady=10)

                # Bind the enter key to the search function
                root.unbind("<Return>")
                root.bind("<Return>", lambda event=None: search())

                root.geometry('1450x801')
                root.protocol("WM_DELETE_WINDOW", disable_close)
            else:
                # Show an error message
                error_label.config(fg="red", text="Invalid username or password")
        else:
            # Show an error message for no result found
            error_label.config(fg="red", text="User not found")

    except Exception as e:
        # Handle exceptions and log the error
        print(f"Error during login: {e}")
        error_label.config(fg="red", text="Error during login.")

    finally:
        connection.close()


# Clears all the text and entry fields
def clear_fields():
    char_text.delete(1.0, END)
    check_entry.delete(0, END)
    search_entry.delete(0, END)
    password_text.delete(1.0, END)
    breach_text.delete(1.0, END)
    passwords_text.delete(1.0, END)
    progressbar.configure(progress_color='gray')
    progressbar.set(0)
    char_slider.set(8)

# Logs the user out and encrypts the passwords file
def logout():
    clear_fields()

    # Hide the main frame
    main_frame.grid_forget()

    # Show the login frame
    login_frame.grid(row=0, column=0, padx=10, pady=10)

    try:
        # Encryption
        connection = sqlite3.connect('description.db')
        cursor = connection.cursor()

        fetch_key = "SELECT password FROM description WHERE username = 'Key'"
        cursor.execute(fetch_key)
        result = cursor.fetchone()

        key = result[0]
        connection.close()

        fernet = Fernet(key)

        with open('KeyGuardian_temp.db', 'rb') as database:
            data = database.read()

        encrypted_data = fernet.encrypt(data)

        with open('KeyGuardian.db', 'wb') as encrypted_database:
            encrypted_database.write(encrypted_data)

        # Delete the temporary file
        os.remove('KeyGuardian_temp.db')

        root.geometry('1450x800')
        error_label.config(fg="green", text="You've been successfully logged out.")

        # Rebind the enter key to the login function
        root.unbind("<Return>")
        root.bind("<Return>", lambda event=None: validate_login())

        root.protocol("WM_DELETE_WINDOW", root.destroy)

    except Exception as e:
        # Handle exceptions and log the error
        print(f"Error during logout: {e}")
        error_label.config(fg="red", text="Error during logout.")

# Generates a symmetric key for encryption derived from the user password
def generate_key(password: str):
    password = bytes(password, "UTF-8")
    salt = bcrypt.gensalt()
    salt_bytes = salt.encode("utf-8")

    base_key = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt_bytes,
        iterations = 600000,
    )
    key = base64.urlsafe_b64encode(base_key.derive(password))

    return key

# Calculates entropy of a string to check the randomness
def calculate_entropy(string):
    entropy = 0
    length = len(string)
    occurrences = {}
    for letter in string:
        if letter in occurrences:
            occurrences[letter] += 1
        else:
            occurrences[letter] = 1
    for letter in occurrences:
        probability = occurrences[letter] / length
        entropy -= probability * math.log2(probability)
    return entropy

# Takes the amount of characters the user desires and generates 
# a secure password with that length.
def password_gen():
    password_text.delete(1.0, END)

    lowerCase = string.ascii_lowercase
    upperCase = string.ascii_uppercase
    digit = string.digits
    symbols = string.punctuation
    password = ""

    # Combining all the data
    data = lowerCase + upperCase + digit + symbols
        
    while calculate_entropy(password) < 3:
        length = int(char_slider.get())
        temp = (
            random.sample(lowerCase, 2)
            + random.sample(upperCase, 2)
            + random.sample(digit, 2)
            + random.sample(symbols, 2)
            + random.sample(data, length - 2 - 2 - 2 - 2)
        )
        random.shuffle(temp)
        password = "".join(temp)

        password_text.insert(1.0, password)

# Takes the entered password and checks it against a wordlist of 
# breached passwords.
def breach_lookup():
    breach_text.delete(1.0, END)
    
    userWord = check_entry.get()

    # Create password policy and give rating
    policy = PasswordPolicy.from_names(
        length=8,  # minimum length 8 characters
        uppercase=2,  # require at least one uppercase letter
        numbers=2,  # require at least one number
        special=2,  # require at least one special character
        entropybits=85  # require a minimum entropy of 85 bits
    )

    strengthTest = policy.test(userWord)

    # Sets the progressbar based on the security scale
    if len(strengthTest) == 0:
        progressbar.set(1)
        progressbar.configure(progress_color='green')
    elif len(strengthTest) == 1:
        progressbar.set(0.80)
        progressbar.configure(progress_color='darkolivegreen3')
    elif len(strengthTest) == 2:
        progressbar.set(0.60)
        progressbar.configure(progress_color='orange')
    elif len(strengthTest) == 3:
        progressbar.set(0.40)
        progressbar.configure(progress_color='red')
    elif len(strengthTest) == 4:
        progressbar.set(0.20)
        progressbar.configure(progress_color='red')

    breached = ""
    current_dir = os.getcwd()

    # Reads in all passwords from the files
    for i in range(1, 9):
        breach_path = os.path.join(current_dir, f"breached_{i}.txt")
        if os.path.exists(breach_path):
            with open(breach_path, "r", encoding="latin-1") as file:
                breached += file.read()

    # Checks the entered password against the breached passwords
    if len(userWord) > 7:
    
        if userWord in breached:
            progressbar.set(0)
            progressbar.configure(progress_color='red')
            breach_text.configure(text_color="red")
            breach_text.insert(0.0, "ALERT! \n\nYour password has been discovered in a previously breached password database. "
                                    "DO NOT use this password for ANY of your online accounts.")
        else:
            breach_text.configure(text_color="green")
            breach_text.insert(0.0, "OK! This password was not discovered in our breached password database.\n\n"
                                    "WARNING: This does NOT mean this password \nhas not been exposed previously. \n"
                                    "Our database is not perfect.")
    else:
        progressbar.set(0)
        progressbar.configure(progress_color='red')
        breach_text.configure(text_color="orange")
        breach_text.insert(0.0, "Warning: Your password is less than 8 characters. It is recomended to use a longer password!")

# Allows the user to add a password to the file
def add():

    # Inserts the user data into the database
    def add_data():
        website = website_entry.get()
        username = username2_entry.get()
        password = pass_entry.get()

        connection = sqlite3.connect('KeyGuardian_temp.db')
        cursor = connection.cursor()

        # Use placeholders (?) and pass the values as a tuple
        insert_pass = "INSERT INTO passwords(Website, Username, Password) VALUES (?, ?, ?)"
        cursor.execute(insert_pass, (website, username, password))
        connection.commit()
        connection.close()

        # Close the window after data insertion
        add_window.destroy()

    # Creates popup window for entries
    add_window = tkinter.Tk()
    add_window.title('Add Password')
    add_window.geometry('400x200+800+200')

    website_label = Label(add_window, text="Enter website:")
    website_label.grid(row=0, column=0, padx=10, pady=10)

    website_entry = customtkinter.CTkEntry(add_window, width=170, height=25)
    website_entry.grid(row=0, column=1, padx=10, pady=10)

    username_label = Label(add_window, text="Enter username:")
    username_label.grid(row=1, column=0, padx=10, pady=10)

    username2_entry = customtkinter.CTkEntry(add_window, width=170, height=25)
    username2_entry.grid(row=1, column=1, padx=10, pady=10)

    pass_label = Label(add_window, text="Enter password:")
    pass_label.grid(row=2, column=0, padx=10, pady=10)

    pass_entry = customtkinter.CTkEntry(add_window, width=170, height=25)
    pass_entry.grid(row=2, column=1, padx=10, pady=10)

    enter_btn = customtkinter.CTkButton(add_window, text="Enter", hover_color='green', width=70, height=25, command=add_data)
    enter_btn.grid(row=3, column=1, padx=2, pady=10)


# Allows the user to remove a password from the file
def remove():

    def remove_data():
        website = website_entry.get()

        connection = sqlite3.connect('KeyGuardian_temp.db')
        cursor = connection.cursor()

        # Search through the database
        search_pass = "SELECT * FROM passwords WHERE website LIKE ?"
        db_website = cursor.execute(search_pass, ('%' + website + '%',)).fetchone()

        def yes():
            # Perform deletion
            delete_pass = "DELETE FROM passwords WHERE website LIKE ?"
            cursor.execute(delete_pass, ('%' + website + '%',))
            
            # Commit the changes to the database
            connection.commit()
            connection.close()

            # Display the removed website
            search_text.delete(1.0, END)
            search_text.insert(END, f"Successfully removed: {db_website[0]}")

            confirm_label.grid_forget()
            yes_btn.grid_forget()
            no_btn.grid_forget()

        # Exit if the user cancels
        def no():
            remove_window.destroy()

        # If an entry is found display search results and prompts user to delete
        if db_website:
            search_text.delete(1.0, END)
            search_text.insert(END, "WEBSITE\t  USERNAME\t\tPASSWORD\n\n")
            search_text.insert(END, f"{db_website[0]}\t  {db_website[1]}\t\t{db_website[2]}")

            confirm_lbl = Label(remove_window, text="Are you sure you want to remove this entry?", font=("Arial", 15))
            confirm_lbl.grid(row=3, column=0, columnspan=2)

            yes_btn = customtkinter.CTkButton(remove_window, text="Yes", hover_color='green', width=60, height=20, command=yes)
            yes_btn.grid(row=4, column=0, pady=30)
            
            no_btn = customtkinter.CTkButton(remove_window, text="No", hover_color='red', width=60, height=20, command=no)
            no_btn.grid(row=4, column=1, pady=30)

        else:
            search_text.delete(1.0, END)
            search_text.insert(END, "Website not found in the database.")

    # Create the remove window UI
    remove_window = tkinter.Tk()
    remove_window.title('Remove Password')
    remove_window.geometry('500x300+800+200')

    website_label = Label(remove_window, text="Enter website to remove:", font=("Arial", 13))
    website_label.grid(row=0, column=0, padx=10, pady=10)

    website_entry = customtkinter.CTkEntry(remove_window, width=150, height=25)
    website_entry.grid(row=0, column=1, padx=10, pady=10)

    enter_btn = customtkinter.CTkButton(remove_window, text="Search", hover_color='green', width=70, height=25, command=remove_data)
    enter_btn.grid(row=1, column=1, padx=2, pady=10)

    search_text = customtkinter.CTkTextbox(remove_window, height=70, width=400, wrap=WORD)
    search_text.grid(row=2, column=0, columnspan=3, pady=20, padx=30)

# Allows the user to search their passwords
def search():
    search = search_entry.get()

    connection = sqlite3.connect('KeyGuardian_temp.db')
    cursor = connection.cursor()

    # Retrieve data from the database using partial match
    query = "SELECT * FROM passwords WHERE website LIKE ?"
    search_data = cursor.execute(query, ('%' + search + '%',)).fetchall()

    # Display the results if found
    if search_data:
        passwords_text.delete(1.0, END)  # Clear previous content
        passwords_text.insert(END, "WEBSITE\t         USERNAME\t\t\tPASSWORD")

        for row in search_data:
            passwords_text.insert(END, f"\n\n{row[0]}\t          {row[1]}\t\t\t{row[2]}")
    else:
        passwords_text.delete(1.0, END)  # Clear previous content
        passwords_text.insert(END, "No matching data found in the database.")


    connection.close()

# Shows all the passwords in the text box
def show_all():
    # Establish database connection
    connection = sqlite3.connect('KeyGuardian_temp.db')
    cursor = connection.cursor()
    query = "SELECT * FROM passwords"
    pass_data = cursor.execute(query).fetchall()

    connection.close()


    # Display the results if found
    if pass_data:
        passwords_text.delete(1.0, END)  # Clear previous content
        passwords_text.insert(END, "WEBSITE\t      USERNAME\t\t\tPASSWORD")

        for row in pass_data:
            passwords_text.insert(END, f"\n\n{row[0]}\t       {row[1]}\t\t\t{row[2]}")
    else:
        passwords_text.delete(1.0, END)  # Clear previous content
        passwords_text.insert(END, "No data found in the database.")


# Hides all the passwords printed in the text box
def hide_all():
    passwords_text.delete(1.0, END)

# Prints the number of characters chosen by the user
def char_number(slider_value):
    slider_value = int(slider_value)
    char_text.delete(1.0, END)
    char_text.insert(1.0, slider_value)

# Copies the password to the clipboard
def copy_text():
    text = password_text.get(1.0, END)
    pyperclip.copy(text)

    check_path = os.path.join(current_dir, "check.jpg")
    check = ImageTk.PhotoImage(Image.open(check_path))
    copy_btn.configure(image=check)
    root.after(1250, restore_image)

# Restores the clipboard image to the copy button
def restore_image():
    copy_btn.configure(image=clipboard)

# Creates the password database and stores it securely
def create_pass():
    connection = sqlite3.connect('description.db')
    cursor = connection.cursor()

    username = user_entry.get()
    password1 = pass_entry.get()
    password2 = confirm_entry.get()

    nomatch_lbl = Label(create_window, text="")

    # If the passwords match, log the user in and create database for encryption key
    if password1 == password2:

        if calculate_entropy(password2) > 3:
            # Create database to store keys
            create_des = "CREATE TABLE IF NOT EXISTS description (username varchar, password varchar)"
            cursor.execute(create_des)

            # Create database to store passwords
            current_dir = os.getcwd()
            kg_path = current_dir + "/KeyGuardian_temp.db"
            
            if not os.path.exists(kg_path):
                conn_kg = sqlite3.connect('KeyGuardian_temp.db')
                cursor2 = conn_kg.cursor()

                create_pass = "CREATE TABLE IF NOT EXISTS passwords(Website varchar, Username varchar, Password varchar)"
                cursor2.execute(create_pass)
                
                conn_kg.commit()
                conn_kg.close
            
            # Hash and store the password
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password2.encode('utf-8'), salt)

            # Stores username and password hash
            store_hash = "INSERT INTO description(username, password) VALUES (?, ?)"
            cursor.execute(store_hash, (username, password_hash))
            connection.commit()

            # Generate encryption key from the password
            enc_key = generate_key(password_hash)

            # Store key in database
            cursor.execute("INSERT INTO description(username, password) VALUES (?, ?)", ("Key", enc_key))
            connection.commit()
            connection.close()

            # Close the prompt window
            create_window.destroy()

            # Hide the login frame and show main frame
            login_frame.grid_forget()
            main_frame.grid(row=0, column=0, padx=10, pady=10)

        else:
            nomatch_lbl.config(fg='red', text="Try a more complex password!")
            nomatch_lbl.grid(row=4, column=1)
    else:
        nomatch_lbl.config(fg='red', text="Passwords do not match. Please try again!")
        nomatch_lbl.grid(row=4, column=1)

# Disables closing window for security reasons
def disable_close():
   pass

# Closes the window
def close_window():
    root.destroy()

# Main Window
root = tkinter.Tk()
root.title('KeyGuardian')
root.iconbitmap('')
root.geometry('1450x800')

# Makes GUI move with window resize
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Login Frame #
login_frame = tkinter.Frame(root)

# Logo
current_dir = os.getcwd()
logo_path = os.path.join(current_dir, "KG_logo.png")
logo = ImageTk.PhotoImage(Image.open(logo_path))

login_logo = Label(login_frame, image=logo)
login_logo.grid(row=0, column=0, padx=585, pady=20)

# If the master password has not been created, this prompts the user to create it
desc_path = current_dir + "/description.db"
if not os.path.exists(desc_path):    
    # Creates popup window for password creation
    create_window = tkinter.Tk()
    create_window.title('Create Password')
    create_window.geometry('450x220+480+440')
    create_window.protocol("WM_DELETE_WINDOW", disable_close)

    user_label = Label(create_window, text="Enter new username:")
    user_label.grid(row=0, column=0, padx=10, pady=10)

    user_entry = customtkinter.CTkEntry(create_window, width=150, height=25)
    user_entry.grid(row=0, column=1, padx=60, pady=10)

    pass_label = Label(create_window, text="Enter password:")
    pass_label.grid(row=1, column=0, padx=10, pady=10)

    pass_entry = customtkinter.CTkEntry(create_window, width=150, height=25, show='●', font=("Arial", 12))
    pass_entry.grid(row=1, column=1, padx=60, pady=10)

    confirm_label = Label(create_window, text="Confirm password:")
    confirm_label.grid(row=2, column=0, padx=10, pady=10)

    confirm_entry = customtkinter.CTkEntry(create_window, width=150, height=25, show='●', font=("Arial", 12))
    confirm_entry.grid(row=2, column=1, padx=10, pady=10)

    create_btn = customtkinter.CTkButton(create_window, text="Create", hover_color='green', width=70, height=25, command=create_pass)
    create_btn.grid(row=3, column=1, padx=60, pady=10)

# Username label and entry
loginUI_frame = customtkinter.CTkFrame(login_frame, corner_radius=15, width=400, height=350)
loginUI_frame.grid(row=1, column=0, pady=20)

username_label = Label(loginUI_frame, text="Username:", bg='gray17')
username_label.grid(row=0, column=0, padx=10, pady=10)

username_entry = customtkinter.CTkEntry(loginUI_frame, width=200)
username_entry.grid(row=0, column=1, padx=10, pady=10)

# Password label and entry
password_label = Label(loginUI_frame, text="Password:", bg='gray17')
password_label.grid(row=1, column=0, padx=10, pady=10)

password_entry = customtkinter.CTkEntry(loginUI_frame, width=200, show='●', font=("Arial", 12))
password_entry.grid(row=1, column=1, padx=10, pady=10)

# Login button
login_button = customtkinter.CTkButton(loginUI_frame, text="Login", hover_color='green', width=100, command=validate_login)
login_button.grid(row=3, column=1, columnspan=2, padx=10, pady=10)

# Bind the enter key to the login function
root.bind("<Return>", lambda event=None: validate_login())

# Error label
error_label = Label(login_frame, font=('Arial', 16))
error_label.grid(row=4, column=0, columnspan=2, pady=40)

## Main Frame ##
main_frame = tkinter.Frame(root)

logo_small_path = os.path.join(current_dir, "KG_logo_small.jpeg")
main_logo = ImageTk.PhotoImage(Image.open(logo_small_path))

logolbl = Label(main_frame, image=main_logo)
logolbl.grid(row=0, column=0)

welcome_label = Label(main_frame, text="Welcome to KeyGuardian!", font=("Arial", 24), fg='green')
welcome_label.grid(row=0, column=1)

# Logout button
logout_btn = customtkinter.CTkButton(main_frame, text="Logout", hover_color='red', width=85, height=27, command=logout)
logout_btn.grid(row=0, column=3)

# Password Generator UI
gen_frame = customtkinter.CTkFrame(main_frame, corner_radius=15, border_width=2, border_color="green")
gen_frame.grid(row=1, column=0, columnspan=2, padx=40)

generator_label = Label(gen_frame, text="Secure Password Generator", font=("Arial", 20), bg='gray17')
generator_label.grid(row=0, column=0, padx=20, pady=20)

char_label = Label(gen_frame, text="Choose number of characters:", font=("Arial", 12), bg='gray17')
char_label.grid(row=1, column=0, pady=10)

char_text = customtkinter.CTkTextbox(gen_frame, width=32, height=25)
char_text.grid(row=0, column=1, padx=10, pady=10)

# Slider for character selection
slider_value = tkinter.IntVar()
char_slider = customtkinter.CTkSlider(gen_frame, from_=8, to=35, variable=slider_value, command=char_number)
char_slider.grid(row=1, column=1)
char_slider.configure(number_of_steps=27, button_color='gray', button_hover_color='green', progress_color='dodgerblue3')
char_slider.set(8)

generator_btn = customtkinter.CTkButton(gen_frame, text="Go", hover_color='green', width=50, height=25, command=password_gen)
generator_btn.grid(row=1, column=2, padx=20, pady=10)

copy_path = os.path.join(current_dir, "copyimg.jpg")
clipboard = ImageTk.PhotoImage(Image.open(copy_path))

copy_btn = customtkinter.CTkButton(gen_frame, text="", image=clipboard, fg_color='black', hover_color='black', width=10, height=10, command=copy_text)
copy_btn.grid(row=2, column=2)

password_text = customtkinter.CTkTextbox(gen_frame, height=25, width=200, wrap=WORD)
password_text.grid(row=2, column=1, padx=10, pady=20)

# Breach Checker UI
breach_frame = customtkinter.CTkFrame(main_frame, corner_radius=15, border_width=2, border_color="green")
breach_frame.grid(row=2, column=0, columnspan=2, padx=20, pady=20)

breach_label = Label(breach_frame, text="Breach Checker", font=("Arial", 20), bg='gray17')
breach_label.grid(row=0, column=0, padx=20, pady=20)

check_label = Label(breach_frame, text="Please Enter Password:", font=("Arial", 12), bg='gray17')
check_label.grid(row=1, column=0, pady=10)

check_entry = customtkinter.CTkEntry(breach_frame, width=250, height=25)
check_entry.grid(row=1, column=1, padx=10, pady=10)

check_btn = customtkinter.CTkButton(breach_frame, text="Go", hover_color='green', width=50, height=25, command=breach_lookup)
check_btn.grid(row=1, column=2, padx=25, pady=10)

breach_text = customtkinter.CTkTextbox(breach_frame, height=115, width=300, wrap=WORD)
breach_text.grid(row=2, column=1, padx=5, pady=20)

# Progress bar for security rating
progressbar = customtkinter.CTkProgressBar(breach_frame, orientation="horizontal", width=250)
progressbar.grid(row=0, column=1)
progressbar.configure(progress_color='gray')
progressbar.set(0)

# Password manager UI
manager_frame = customtkinter.CTkFrame(main_frame, corner_radius=15, border_width=2, border_color="green")
manager_frame.grid(row=1, column=2, rowspan=2, columnspan=2, padx=20, pady=20)

manager_label = Label(manager_frame, text="Secure Password Manager", font=("Arial", 20), bg='gray17')
manager_label.grid(row=0, column=0, columnspan=2, padx=20, pady=20)

passwords_text = customtkinter.CTkTextbox(manager_frame, height=400, width=500, wrap=WORD)
passwords_text.grid(row=3, column=0, columnspan=4, padx=20, pady=20)
passwords_text.configure(font=("Arial", 14))

add_btn = customtkinter.CTkButton(manager_frame, text="Add", hover_color='green', width=70, height=25, command=add)
add_btn.grid(row=1, column=2, padx=2, pady=10)

remove_btn = customtkinter.CTkButton(manager_frame, text="Remove", hover_color='green', width=70, height=25, command=remove)
remove_btn.grid(row=2, column=2, padx=2, pady=10)

search_btn = customtkinter.CTkButton(manager_frame, text="Search", hover_color='green', width=70, height=25, command=search)
search_btn.grid(row=2, column=1, padx=2, pady=10)

show_btn = customtkinter.CTkButton(manager_frame, text="Show All", hover_color='green', width=70, height=25, command=show_all)
show_btn.grid(row=1, column=0, padx=2, pady=10)

search_entry = customtkinter.CTkEntry(manager_frame, width=150, height=25)
search_entry.grid(row=2, column=0, pady=10)

hide_btn = customtkinter.CTkButton(manager_frame, text="Hide All", hover_color='green', width=70, height=25, command=hide_all)
hide_btn.grid(row=1, column=1, padx=2, pady=10)

# Initially, hide the main frame
main_frame.grid_forget()

# Show the login frame
login_frame.grid(row=0, column=0, padx=10, pady=10)

# Start the main event loop
root.mainloop()
