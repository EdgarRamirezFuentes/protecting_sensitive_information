from Crypto.Hash import SHA3_256

password = input("Password: ")
h = SHA3_256.new(bytes(password, 'utf-8'))
print(h.hexdigest(), len(h.hexdigest()), len("edgar.alejandro.fuentes98@gmail.com"))