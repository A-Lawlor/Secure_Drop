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
import threading
import cryptocode
import socket
import json
import os.path
import tqdm
import os
import hashlib


class user:
    def __init__(self, name, email, password, salt):
        self.name = name
        self.email = email
        self.password = password
        self.salt = salt
        self.ip = '127.0.0.1'
        self.port = []

class contact:
    def __init__(self):
        self.name = []
        self.email = []
        self.online = False
        self.ip = '127.0.0.1'
        self.port = []

class onlineStatus(enum.Enum):
    online = 'online'
    offline = 'offline'

def getRandomPort(s):
    retv = int(hashlib.sha256(s.encode('utf-8')).hexdigest(), 16) % 10 ** 4
    return retv

def getUserContacts(userAccount):
    if (os.path.exists('%s.name.txt' % userAccount.email) == False) and (os.path.exists('%s.email.txt' % userAccount.email) == False) and (os.path.exists('%s.port.txt' % userAccount.email) == False):
        myName = open('%s.name.txt' % userAccount.email, "a+")
        myEmail = open('%s.email.txt' % userAccount.email, "a+")
        myPort = open('%s.port.txt' % userAccount.email, "a+")
        myName.close()
        myEmail.close()
        myPort.close()
        userC = contact()
        return userC

    if (os.stat('%s.name.txt' % userAccount.email).st_size == 0) and (os.stat('%s.email.txt' % userAccount.email).st_size == 0) and (os.stat('%s.port.txt' % userAccount.email).st_size == 0):
        userC = contact()
        return userC
    else:
        myName = open('%s.name.txt' % userAccount.email, "r+")
        myEmail = open('%s.email.txt' % userAccount.email, "r+")
        myPort = open('%s.port.txt' % userAccount.email, "r+")
        eName = myName.read()
        eEmail = myEmail.read()
        ePort = myPort.read()
        eName = cryptocode.decrypt(eName, userAccount.password)
        eEmail = cryptocode.decrypt(eEmail, userAccount.password)
        ePort = cryptocode.decrypt(ePort, userAccount.password)
        userC = contact()   #Creating contact object to interact with the user terminal

        jsonName = json.loads(eName)
        jsonEmail = json.loads(eEmail)
        jsonPort = json.loads(ePort)
        for x in range((len(jsonName["name"]))):
             userC.name.append((jsonName["name"][x]))
        for x in range((len(jsonEmail["email"]))):
            userC.email.append((jsonEmail["email"][x]))
        for x in range((len(jsonPort["port"]))):
            userC.port.append((jsonPort["port"][x]))
        myName.close()
        myEmail.close()
        myPort.close()
        return userC



def loadAccount():
    with open("accountfile.txt", "r") as jsonFile:
        myJson = json.load(jsonFile)
        userAccount = user(myJson["name"], myJson["email"], myJson["password"], myJson["salt"])
        userAccount.ip = myJson["ip"]
        userAccount.port = myJson['port']
        return userAccount

#Check if accountfile.txt exists
def accountFileExists():
    file_path = "accountfile.txt"
    if not os.path.exists(file_path):
        f = open(file_path, "x")
        f.close()
    return

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
            temp = str(newUser.email)
            print(temp)
            newUser.port = getRandomPort(temp)
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
        print("Successful exited out of secure drop. ")
        sys.exit()

    password = getpass("Enter Password: ").rstrip(' ')

    encryptedPassword = encrypt(password + userAccount.salt).hexdigest()

    if encryptedPassword == userAccount.password and userName == userAccount.email:
            userTerminal(userAccount)
    else:
        print("\nIncorrect username or password. ")
        login()

#User terminal to define the commands entered such as 'help' and 'add', etc...
def userTerminal(userAccount):
    userC = getUserContacts(userAccount) #Create user contact
    H = threading.Thread(name='host', target=socketHost, args=(userAccount.ip, int(userAccount.port),))  # Start host socket in another thread
    H.start()
    print("Welcome to SecureDrop.")
    print("Type \"help\" For Commands.\n")

    while True:
        userInput = input("secure_drop> ")
        if userInput == 'add':
            userC = add(userAccount, userC)
        elif userInput == 'send':
            send(userAccount, userC)
        elif userInput == 'exit':
            __exit(H)
        elif userInput == 'list':
            list(userC)
        elif userInput == 'help':
            help()

#Exit secure drop terminal
def __exit(H):
    print("Successful logged out of secure drop. ")
    sys.exit()


#Help command print out for secure drop terminal
def help():
    print("\"add\" -> Add a new contact")
    print("\"send\" -> Transfer file to contact")
    print("\"exit\" -> Exit SecureDrop")
    return

def webview_file_dialog():
    file = None

    def open_file_dialog(w):
        nonlocal file
        try:
            file = w.create_file_dialog(webview.OPEN_DIALOG)[0]
        except TypeError:
            pass  # user exited file dialog without picking
        finally:
            w.destroy()

    window = webview.create_window("", hidden=True)
    webview.start(open_file_dialog, window)
        # file will either be a string or None
    return file


def send(userAccount, userC):
    print("Select File to SecureDrop")
    path = webview_file_dialog()
    if(path == None):
        print("No File Selected\n")
        print("Welcome to SecureDrop.")
        print("Type \"help\" For Commands.\n")
        return
    tempEmail = input("Who Would You Like to Send This File to (Email): ")
    if tempEmail in userC.email:
        _index = userC.email.index(tempEmail)
        C = threading.Thread(name='client', target=socketClient, args=(path, userC.port[_index], userAccount,))
        C.start()
        while True:
            if not C.is_alive():
                return

    else:
        print("Invalid Contact")
        user

def list(userC):
        print("Contacts:")
        for x in range(len(userC.name)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((userC.ip, userC.port[x]))

            if(result == 0):
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
        myPort = open('%s.port.txt' % userAccount.email, "r+")
        userC.name.append(input("Enter Full Name: "))
        temp = input("Enter Email Address: ")
        userC.email.append(temp)
        userC.port.append(getRandomPort(temp))
        eName = json.dumps({'name': userC.name})
        eEmail = json.dumps({'email': userC.email})
        ePort = json.dumps({'port': userC.port})
        eName = cryptocode.encrypt(eName, userAccount.password)
        eEmail = cryptocode.encrypt(eEmail, userAccount.password)
        ePort = cryptocode.encrypt(ePort, userAccount.password)
        myName.write(eName)
        myEmail.write(eEmail)
        myPort.write(ePort)
        myName.close()
        myEmail.close()
        myPort.close()
        print("Contact Added. ")
        return userC
    else:
        myName = open('%s.name.txt' % userAccount.email, "r+")
        myEmail = open('%s.email.txt' % userAccount.email, "r+")
        myPort = open('%s.port.txt' % userAccount.email, "r+")
        myName.truncate(0)
        myEmail.truncate(0)
        myPort.truncate(0)
        userC.name.append(input("Enter Full Name: "))
        temp = input("Enter Email Address: ")
        userC.email.append(temp)
        userC.port.append(getRandomPort(temp))
        eName = json.dumps({'name': userC.name})
        eEmail = json.dumps({'email': userC.email})
        ePort = json.dumps({'port': userC.port})
        eName = cryptocode.encrypt(eName, userAccount.password)
        eEmail = cryptocode.encrypt(eEmail, userAccount.password)
        ePort= cryptocode.encrypt(ePort, userAccount.password)
        myName.write(eName)
        myEmail.write(eEmail)
        myPort.write(ePort)
        myName.close()
        myEmail.close()
        myPort.close()
        print("Contact Added. ")
        return userC

def socketHost(ip, port):
    SERVER_HOST = ip
    SERVER_PORT = port
    BUFFER_SIZE = 4096
    SEPARATOR = "<SEPARATOR>"

    s = socket.socket()
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(10)
    while True:
        while True:
            conn, addr = s.accept()
            confirmation = conn.recv(1024)
            dataFromClient = confirmation.decode('utf-8')
            confirmation2 = conn.recv(1024)
            dataFromClient2 = confirmation2.decode('utf-8')
            if(dataFromClient+dataFromClient2):
                print('\n' + dataFromClient+dataFromClient2)
                if input() == 'y':
                     data = 'y'
                     conn.send(data.encode())
                     received = conn.recv(BUFFER_SIZE).decode()
                     filename, filesize = received.split(SEPARATOR)
                     filename = os.path.basename(filename)
                     filesize = int(filesize)
                     progress = tqdm.tqdm(range(filesize), "Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
                     with open(filename, "wb") as f:
                        while True:
                             bytes_read = conn.recv(BUFFER_SIZE)
                             if not bytes_read:
                                 break
                             f.write(bytes_read)
                             progress.update(len(bytes_read))
                        progress.close()
                        s.close()
                        print("Data Received\n")
                        print("Welcome to SecureDrop.")
                        print("Type \"help\" For Commands.\n")
                        print("secure_drop> ")
                        sys.stdout.write('')
                        return
            if not dataFromClient:
                break


def socketClient(path, portConnect, userAccount):
        SEPARATOR = "<SEPARATOR>"

        BUFFER_SIZE = 4096

        s = socket.socket()

        host = "127.0.0.1"
        port = portConnect
        s.connect((host, port))

        filename = path
        data = userAccount.email
        data = str(data)
        s.send(data.encode())
        data2 = 'is sending a file. Accept (y/n)?'
        s.send(data2.encode())
        confirmation = s.recv(1024)
        if(confirmation.decode('utf-8') == 'y'):
            filesize = os.path.getsize(filename)

            s.send(f"{filename}{SEPARATOR}{filesize}".encode())

            # file = open(filename, 'wb')

            progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)

            with open(filename, "rb") as f:

                while True:

                    bytes_read = f.read(BUFFER_SIZE)

                    if not bytes_read:
                        break

                    s.sendall(bytes_read)

                    progress.update(len(bytes_read))
            s.close()
        else:
            print("File Transfer Failed")
            s.close()
            return

    # Run the welcome screen function to start off the program#
welcomeScreen()
