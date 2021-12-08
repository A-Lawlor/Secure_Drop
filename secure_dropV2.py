# To run go to shell then type:
# pip install cryptocode
# pip install pycryptodome
# Then hit run
import webview
import secrets
import os.path
import sys
from Crypto.Hash import SHA256
from getpass import getpass
import cryptocode
import socket
import json

class user:
    def __init__(user, name, email, password, salt):
        user.name = name
        user.email = email
        user.password = password
        user.salt = salt

def loadAccount():
    with open("accountfile.txt", "r") as jsonFile:
        data = json.load(jsonFile)
        userAccount = user(data["name"], data["email"], data["password"], data["salt"])
        return userAccount

#Check if accountfile.txt exists
def accountFileExists():
    file_path = "accountfile.txt"
    if not os.path.exists(file_path):
        f = open(file_path, "x")
        f.close()
    return

def selectFile():
    def webview_file_dialog():  # Opens user select file window
        pathtofile = None

        def open_file_dialog():
            nonlocal pathtofile
            try:
                pathtofile = w.create_file_dialog(webview.OPEN_DIALOG)[0]
            except TypeError:
                pass  # Exit select box without picking
            finally:
                w.destroy()

        window = webview.create_window("", hidden=True)
        webview.start(open_file_dialog, window)
        # file will either be a string or None
        return pathtofile

#encrypt password with SHA256 algorithm to be added to random salt generated
def encrypt(stringLiteral):
    stringByte = stringLiteral.encode('UTF-8')
    hash = SHA256.new()
    hash.update(stringByte)
    return hash

#Register a new or another user
def register():
    accountFileExists()
    file_path = "accountfile.txt"
    if os.stat(file_path).st_size != 0:
        print("A user is already register with this account")
        print("Returning to login screen\n\n")
        welcomeScreen()

    fullName = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    while True:
        salt = secrets.token_hex(8)
        password = getpass("Enter Password: ")
        password = encrypt(password + salt).hexdigest()
        passwordCheck = getpass("Re-Enter Password: ")
        passwordCheck = encrypt(passwordCheck + salt).hexdigest()

        if (password != passwordCheck):
            print("\nPasswords do not match.")

        else:
            print("\nPasswords match.")
            print("User Registered.")
            print("Exiting SecureDrop.")
            newUser = user(fullName, email, password, salt)
            with open("accountfile.txt", "a+") as jsonFile:
                json.dump(vars(newUser), jsonFile)
            return

#Login will direct you to reigster if no users exists otherwise it will ask for a username and password that will bring you to the userTerminal
def login():

    userAccount = loadAccount()

    userName = input("Please enter your email or \"quit\" to exit: ")

    if userName == 'quit':
        _exit()

    else:
        password = getpass("Enter Password: ").rstrip(' ')

    print("Username entered", userName)
    print("username in the object", userAccount.name)

    if userName == userAccount.email:

        encryptedPassword = encrypt(password + userAccount.salt).hexdigest()

    if encryptedPassword == userAccount.password:
            userTerminal(userName, password)
    else:
        print("\nIncorrect username or password. ")
        login()


#Welcoem screen that dictates if you want to register or login into secure drop
def welcomeScreen():
    file_path = 'accountfile.txt'
    print("Welcome to Secure_Drop ")
    welcomeSelection = input("Would you like to (register or login)?: ")

    if welcomeSelection == "register":

        register()

    elif welcomeSelection == "login":

        accountFileExists()
        if os.stat(file_path).st_size == 0:
            print("No users are registered with this client.")

            if input("Do you want to register a new user (y/n): ") == 'y':
                register()
        else:
            login()

    else:
        print("Command not recognized. ")
        welcomeScreen()






#Add user command which gives the user their own data file to store emails and contact names with a cryptocode encrypt funciton
def add(userName, password):
    # new contacts file for user
    if os.path.exists('%s.txt' % userName) == False:
        name = input("Enter Full Name: ")
        emailAddress = input("Enter Email Address: ")
        file = open('%s.txt' % userName, "a+")
        file.write(name)
        file.write("          ")
        file.write(emailAddress)
        file.write("\n")
        file.close()
        file = open('%s.txt' % userName, "a+")
        file.seek(0)
        original = file.read()
        file.truncate(0)
        encrypted = cryptocode.encrypt(original, password)
        file.write(encrypted)
        file.close()
        print("Contact Added. ")
        return
    else:
        file = open('%s.txt' % userName, "a+")
        file.seek(0)
        encrypted = file.read()
        file.truncate(0)
        file.close()
        decrypted = cryptocode.decrypt(encrypted, password)
        file = open('%s.txt' % userName, "a+")
        name = input("Enter Contact Name: ")
        emailAddress = input("Enter Email Address: ")
        file.write(decrypted)
        file.write(name)
        file.write("          ")
        file.write(emailAddress)
        file.write("\n")
        file.seek(0)
        original = file.read()
        file.truncate(0)
        encrypted = cryptocode.encrypt(original, password)
        file.write(encrypted)
        file.close()
        print("Contact Added. ")
        return



#User terminal to define the commands entered such as 'help' and 'add', etc...
def userTerminal(userName, password):
    print("Welcome to SecureDrop.")
    print("Type \"help\" For Commands.\n")


    while (True):
        userInput = input("secure_drop> ")
        if userInput == 'add':
            add(userName, password)
        elif userInput == 'send':
            send()
        elif userInput == 'exit':
            _exit()
        elif userInput == 'list':
            list(userName, password)
        elif userInput == 'help':
            help()
        else:
            print("Invalid command. ")
            # eval(userInput+'()')

#Exit secure drop terminal
def _exit():
    print("Successful logged out of secure drop. ")
    sys.exit()

#Help command print out for secure drop terminal
def help():
    print("\"add\" -> Add a new contact")
    print("\"send\" -> Transfer file to contact")
    print("\"exit\" -> Exit SecureDrop")
    return

def send():
    print("Select File to SecureDrop")

    path =selectFile()
    text = open('%s' % webview_file_dialog(), "r+")
    print(webview_file_dialog())
    webview_file_dialog()
   # textout = text.seek(0)
    #print(textout)
    ##print(webview_file_dialog())

    return

def list(userName, password):
    if os.stat('%s.txt' % userName).st_size == 0:
        print("No Contacts Associated with this User")
        return
    else:
        print("Contacts:")
        print("Name:         Email:")
        file = open('%s.txt' % userName, "r+")
        file.seek(0)
        encrypted = file.read()
        file.close()
        decrypted = cryptocode.decrypt(encrypted, password)
        print(decrypted)
        return





def socketStart():
    HOST = '127.0.0.1'  # Symbolic name, meaning all available interfaces
    PORT = 8889  # Arbitrary non-privileged port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    # Bind socket to local host and port
    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()

    print('Socket bind complete')

    # Start listening on socket
    s.listen(10)
    print('Socket now listening')

    # now keep talking with the client
    while 1:
        # wait to accept a connection - blocking call
        conn, addr = s.accept()
        selectFile()
        print('Connected with ' + addr[0] + ':' + str(addr[1]))
    s.close()

#Run the welcome screen function to start off the program#
#socketStart()
welcomeScreen()