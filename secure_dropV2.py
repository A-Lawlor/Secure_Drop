# To run go to shell then type:
# pip install cryptocode
# pip install pycryptodome
# Then hit run
import colorama
from colorama import Fore, Style
import webview
import enum
import secrets
import os.path
import sys
from Crypto.Hash import SHA256
from getpass import getpass
import subprocess
import cryptocode
import socket
import json

class user:
    def __init__(self, name, email, password, salt):
        self.name = name
        self.email = email
        self.password = password
        self.salt = salt

class contact:
    def __init__(self):
        self.name = []
        self.email = []
        self.online = False

class onlineStatus(enum.Enum):
    online = 'online'
    offline = 'offline'

def getUserContacts(userAccount):
    if (os.path.exists('%s.name.txt' % userAccount.email) == False) and (os.path.exists('%s.email.txt' % userAccount.email) == False):
        myName = open('%s.name.txt' % userAccount.email, "a+")
        myEmail = open('%s.email.txt' % userAccount.email, "a+")
        userC = contact()
        return userC

    if (os.stat('%s.name.txt' % userAccount.email).st_size == 0) and (os.stat('%s.email.txt' % userAccount.email).st_size == 0):
        userC = contact()
        return userC
    else:
        print("getting here in else")
        myName = open('%s.name.txt' % userAccount.email, "r+")
        myEmail = open('%s.email.txt' % userAccount.email, "r+")

    userC = contact()   #Creating contact object to interact with the user terminal

    jsonName = json.load(myName)
    jsonEmail = json.load(myEmail)
    for x in range((len(jsonName["name"]))):
         userC.name.append((jsonName["name"][x]))
    for x in range((len(jsonEmail["email"]))):
        userC.email.append((jsonEmail["email"][x]))
    myName.close()
    myEmail.close()
    return userC





def loadAccount():
    with open("accountfile.txt", "r") as jsonFile:
        myJson = json.load(jsonFile)
        userAccount = user(myJson["name"], myJson["email"], myJson["password"], myJson["salt"])
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


#Login will direct you to reigster if no users exists otherwise it will ask for a username and password that will bring you to the userTerminal
def login():

    userAccount = loadAccount()

    userName = input("Please enter your email or \"quit\" to exit: ")

    if userName == 'quit':
        _exit()
    else:
        password = getpass("Enter Password: ").rstrip(' ')

    if userName == userAccount.email:

        encryptedPassword = encrypt(password + userAccount.salt).hexdigest()

    if encryptedPassword == userAccount.password:
            userTerminal(userAccount)
    else:
        print("\nIncorrect username or password. ")
        login()

#User terminal to define the commands entered such as 'help' and 'add', etc...
def userTerminal(userAccount):
    userC = getUserContacts(userAccount) #Create user contact
    print("Welcome to SecureDrop.")
    print("Type \"help\" For Commands.\n")

    while (True):
        userInput = input("secure_drop> ")
        if userInput == 'add':
            userC = add(userAccount, userC)
        elif userInput == 'send':
            send()
        elif userInput == 'exit':
            _exit()
        elif userInput == 'list':
            list(userC)
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

def list(userC):
        print("Contacts:")
        for x in range(len(userC.name)):

            if(userC.online == "True"):
                print("Name:", userC.name[x],"\tEmail:", userC.email[x], Fore.GREEN + "\tonline", Fore.RESET + "" )
            else:

                print("Name:", userC.name[x],"\tEmail:", userC.email[x], Fore.RED + "\toffline", Fore.RESET + "")
        return

#Add user command which gives the user their own data file to store emails and contact names with a cryptocode encrypt funciton
def add(userAccount, userC):
    # creating new contacts file for user if one does not exist with 'userAccount.email'.txt as the structure
    if ((os.stat('%s.name.txt' % userAccount.email).st_size == 0) and (os.stat('%s.email.txt' % userAccount.email) == 0)):
        myName = open('%s.name.txt' % userAccount.email, "r+")
        myEmail = open('%s.email.txt' % userAccount.email, "r+")
        userC.name.append(input("Enter Full Name: "))
        userC.email.append(input("Enter Email Address: "))
        json.dump({'name': userC.name}, myName)
        json.dump({'email': userC.email}, myEmail)
        print("Contact Added. ")
        myName.close()
        myEmail.close()
        return userC
    else:
        print("getting here")
        myName = open('%s.name.txt' % userAccount.email, "r+")
        myEmail = open('%s.email.txt' % userAccount.email, "r+")
        myName.truncate(0)
        myEmail.truncate(0)
        userC.name.append(input("Enter Full Name: "))
        userC.email.append(input("Enter Email Address: "))
        json.dump({'name': userC.name}, myName)
        json.dump({'email': userC.email}, myEmail)
        print("Contact Added. ")
        return userC


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