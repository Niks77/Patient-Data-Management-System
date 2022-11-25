from decouple import config
from fcs_project import settings
import gmpy2
from gmpy2 import mpz
import re
import os
import hashlib
e = config('E')
n = config('N')
d = config('D')



def decrypt(hash):
    s = ''
    for i in hash:
        s += chr(gmpy2.powmod(int(i), int(d), int(n)))
    return s

def encrypt(hash):
  
    s = []
    for i in hash.encode():
        s.append(gmpy2.powmod(i, e, n))
    
    return s

def stringToMPZ(content):
    y_val3 = [mpz(element) for element in re.findall(r'mpz\(([0-9]+)\)', content)]
    return y_val3

def verifyfile(cipher, username,fileverify):
    if cipher is None:
        return False
    
    s = ''
    print(cipher.path)
    print(fileverify.path)
    try:
        
        with open(cipher.path, "r") as f:
            s = f.read().replace("\n", "")

    except:
        return False
    
    print("hii")
    hash = decrypt(stringToMPZ(s))
    print(hash)
  
    sha256_hash = hashlib.sha256()
    try:

        with open(fileverify.path,"rb") as f:
            print("hii")
            for byte_block in iter(lambda: f.read(4096),b""):
                if byte_block is not None:
                    sha256_hash.update(byte_block)
            new_hash = sha256_hash.hexdigest()
            print(new_hash)
            return username + new_hash == hash
    except:
        return False
    

def generate_key(username,file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                if byte_block is not None:
                    sha256_hash.update(byte_block)
            new_hash = sha256_hash.hexdigest()
            return encrypt(username + str(new_hash))
    except:
        pass

        
