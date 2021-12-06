import cryptocode

password = "hey"
message = "Testing123"

encrypted = cryptocode.encrypt(message, password)
print(encrypted)
decrypted = cryptocode.decrypt(encrypted, password)
print(decrypted)