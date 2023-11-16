# KeyGuardian

KeyGuardian is a password generator, checker, and manager of passwords that are stored securely in a local database. This software also helps educate users on better protecting their online accounts.

## Compile/Deploy

This software is multi-platform and works on any OS. First, clone the repository:

```
$ git clone https://github.com/logon02/CSU-Senior-Project.git
```

The latest version of Python must be installed and all these packages with the commands listed below:

```
$ pip install tkinter
$ pip install customtkinter
$ pip install sqlite3
$ pip install pillow
$ pip install cryptography
$ pip install password_strength
$ pip install pyperclip
$ pip install bcrypt
```

Once the repository is cloned and all the packages are installed the program is ready to be run! You can run it from a terminal by navigating to the /CSU-Senior-Project/ directory and use this command:

```
$ python3 KeyGuardian.py
```

Another way to run the program is through Visual Studio Code. In VS Code, open the /CSU-Senior-Project/ folder and click the run button at the top right of the screen. You may have to select the latest version of Python in order to run KeyGuardian successfully. If you have any questions about running the software please email me: lcferguson@csustudent.net

## Usage

KeyGuardian is a password generator, manager, and breach checker. You can easily create an account with a master password on the first execution of the software on your system, generate secure passwords, and store them securely in a local, fully encrypted database. You can also check currently used passwords or even newly generated passwords for security with the KeyGuardian breach checker. This software uses advanced symmetric encryption algorithms including SHA256 using bcrypt, PBKDF2, and HMAC. Feel free to use KeyGuardian for any of your passwords!

## Options

## Testing

