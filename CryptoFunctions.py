import numpy as np
import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
import random 
from math import pow, gcd

@staticmethod
def cesar(plaintext, s=13):
    """
    Excrypt a text using Cesar Cipher (coding utf-8)
    
    args:
        plaintext (str): original text to encrypt

    returns:
        ciphertext (str): text after encryption
    """
    ciphertext = ""

    for i in range(len(plaintext)):
        char = plaintext[i]

        if char.isupper():
            ciphertext += chr((ord(char) + s - 65) % 26 + 65)

        elif char.islower():
            ciphertext += chr((ord(char) + s - 97) % 26 + 97)
            
        else:
            if ord(char) >= 98:
                ciphertext += chr(ord(char)+ s)
            
            elif ord(char) <= 64:
                ciphertext += chr((ord(char)+ s) % 65)
            
            elif ord(char) >= 91 and ord(char) <=96 :
                ciphertext += chr((ord(char)+ s - 91) % 6 + 91)

    return ciphertext

@staticmethod
def de_cesar(ciphertext, s=13):
    """
    Decrypt a text using Cesar Cipher (coding utf-8)
    
    args:
        ciphertext (str): text to decrypt

    returns:
        plaintext (str): text after decryption
    """
    plaintext = ""

    for i in range(len(ciphertext)):
        char = ciphertext[i]

        if char.isupper():
            plaintext += chr((ord(char) - s - 65) % 26 + 65)

        if char.islower():
            plaintext += chr((ord(char) - s - 97) % 26 + 97)

        else:
            if ord(char) >= 98:
                plaintext += chr(ord(char)- s)
            
            elif ord(char) <= 64:
                plaintext += chr((ord(char)- s) % 65)
            
            elif ord(char) >= 91 and ord(char) <=96 :
                plaintext += chr((ord(char)- s - 91) % 6 + 91)

    return plaintext

@staticmethod
def atbash(plaintext):
    """
    Encrypt a text using AtBash Cipher (coding utf-8)
    
    args:
        plaintext (str): original text to encrypt

    returns:
        ciphertext (str): text after encryption
    """
    ciphertext = ""

    for i in range(len(plaintext)):
        char = plaintext[i]

        if char.isupper():
            ciphertext += chr(65 + 90 - ord(char))

        else:
            ciphertext += chr(97 + 122 - ord(char))

    return ciphertext

@staticmethod
def de_atbash(ciphertext):
    """
    Decrypt a text using AtBash Cipher (coding utf-8)

    args:
        ciphertext (str): text to decrypt

    returns:
        plaintext (str): text after decryption
    """
    plaintext = ""

    for i in range(len(ciphertext)):
        char = ciphertext[i]

        if char.isupper():
            plaintext += chr(65 + 90 - ord(char))

        else:
            plaintext += chr(97 + 122 - ord(char))

    return plaintext

@staticmethod
def transpColumn(plaintext, key='abc'):
    """
    Encrypt a text using Columnar Transposition Cipher (coding utf-8)
    
    args:
        plaintext (str): original text to encrypt
        key (str): secret key (hint: do not use "password")

    returns:
        ciphertext (str): text after encryption
    """
    ciphertext=""
    b=''
    n=len(key)
    aux=int(len(plaintext)/n + 1)
    aux= aux, n
    Matriz = np.zeros(aux)
    count=0
    countkey=1
    auxkey= 1, n
    keyaux= np.zeros(auxkey)

    for i in range(aux[0]):
        for j in range(n):
            if count < len(plaintext):
                Matriz[i][j]=ord(plaintext[count])
                count +=1
    
    if key.isalpha()==True:
        key.upper()
   
    for i in range(len(key)):
        b = min(key)
        a = key.find(b)
        keyaux[0][i]= a
        key = key.replace(b, chr(231), 1)
        countkey+=1
    
    for i in range(n):
        c = int(keyaux[0][i])
        aux2=Matriz[:, c]
        for j in range(len(aux2)):
            if int(aux2[j])!=0:
                ciphertext += chr(int(aux2[j]))

    return ciphertext

@staticmethod
def de_transpColumn(ciphertext, key='abc'):
    """
    Decrypt a text using Columnar Transposition Cipher (coding utf-8)
    
    args:
        ciphertext (str): text to decrypt
        key (str): secret key (hint: do not use "password")

    returns:
        plaintext (str): text after decryption
    """
    plaintext=""
    n=len(key)
    aux=int(len(ciphertext)/n + 1)
    aux= aux, n
    Matriz = np.zeros(aux)
    count=0
    countkey=1
    auxkey= 1, n
    keyaux= np.zeros(auxkey)

    if key.isalpha()==True:
        key.upper()
   
    for i in range(len(key)):
        b = min(key)
        a = key.find(b)
        keyaux[0][i]= a
        key = key.replace(b, chr(231), 1)
        countkey+=1
    
    for i in range(n):
        for j in range(aux[0]):
            if j == aux[0]-1 and c>len(ciphertext) % n -1:
                continue
            if count < len(ciphertext):
                c = int(keyaux[0][i])
                Matriz[j][c]=ord(ciphertext[count])
                count +=1
    
    for i in range(aux[0]):
        aux2=Matriz[i,:]
        for j in range(len(aux2)):
            if int(aux2[j])!=0:
                plaintext += chr(int(aux2[j]))
    
    return plaintext

@staticmethod
def vigenere(plaintext, key='demar'):
    """
    Encrypt a text using viegenere Cipher (coding utf-8)

    args:
        plaintext (str): text to encrypt
        key (str): secret key (hint: do not use "Password")

    returns:
        ciphertext (str): text after encryption
    """
    ciphertext=""
    numchave=[]
    count=0

    for i in range(len(key)):
        if key[i].isupper() == True:
            numchave.append(ord(key[i])-ord('A'))
        else:
            numchave.append(ord(key[i])-ord('a'))
    for i in range(len(plaintext)):
        aux=count%len(key)
        char = cesar(plaintext[i],numchave[aux])
        count +=1
        ciphertext += char

    return ciphertext

@staticmethod
def de_vigenere(ciphertext, key='demar'):
    """
    Decrypt a text using Vigenere Cipher (coding utf-8)

    args:
        ciphertext (str): text to decrypt
        key (str): secret key (hint: do not use "Password")
    
    returns:
        plaintext (str): text after decryption
    """
    plaintext=''
    numchave=[]
    count=0

    for i in range(len(key)):
        if key[i].isupper() == True:
            numchave.append(ord(key[i])-ord('A'))
        else:
            numchave.append(ord(key[i])-ord('a'))
    for i in range(len(ciphertext)):
        aux=count%len(key)
        char = de_cesar(ciphertext[i],numchave[aux])
        count +=1
        plaintext += char

    return plaintext

@staticmethod
def onetimepad(plaintext, key, encoding='utf-8'):
    """
    Bytes encrypt using OneTimePad Cipher 

    args:
        plaintext (str): text to encrypt
        key (str): secret key
        encoding: utf-8 if not provided

    returns:
        ciphertext (str): text after encryption
    """
    ciphertext=bytes()
    
    if isinstance(plaintext, bytes) == False:
        if isinstance(plaintext, str) == True:
            plaintext=bytes(plaintext, encoding)
        else:
            plaintext=bytes(str(plaintext), encoding)
    
    if isinstance(key, bytes) == False:
        if isinstance(key, str) == True:
            key=bytes(key, encoding)
        else:
            key=bytes(str(key), encoding)
    
    while len(key) <= len(plaintext):
        key += key

    for p, k in zip( plaintext, key ):
        xor = p ^ k
        ciphertext += bytes([xor])

    return ciphertext

@staticmethod
def de_onetimepad(ciphertext, key, encoding='utf-8'):
    """
    Bytes decrypt using OneTimePad Cipher 

    args:
        ciphertext (str): text to decrypt
        key (str): secret key
        encoding: utf-8 if not provided

    returns:
        plaintext (str): text after decryption
    """

    return onetimepad(ciphertext, key, encoding)

class AESCipher(object):
    '''
    Can cript/decript using Advanced Encryption Standart

    object (str): a secret key to hide/reveal an information 

    How to use:
        crypted_in_AES = AESChiper(key).encrypt(plain_text)

        decrypted_in_AES = AESChiper(key).decrypt(chiper_text)
    '''

    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest() 

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(str(plain_text)) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = str(plain_text) + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(str(plain_text)) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]

    def encrypt(self, plain_text):
        '''
        Encrypt the plain text using Advanced Encryption Standart algorithm

        args:
            plain_text (str, int, float): text that you want to hide

        returns:
            cipher text (bytes): plain text after encryption
        '''
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())

        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        '''
        Decrypt the plain text using Advanced Encryption Standart algorithm

        args:
            encrypted_text (bytes): cipher text with Advanced Encryption Standart algorithm
        
        returns:
            plain text (str, int, float): cipher text after decryption

        raises:
            Exception: Can't decode this information.
        '''
        try:
            encrypted_text = b64decode(encrypted_text)
        except:
            raise Exception("Can't decode this information.")
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")

        return self.__unpad(plain_text)

class ECCCipher(object):
	'''
	Can cript/decript using Elliptic Curve Cryptography
     
    How to use:
        crypted_in_ECC = ECCChiper.encrypt(plain_text)

        decrypted_in_ECC = ECCChiper.decrypt(cipher_text, public_key, key_receptor)
	'''

	def __init__(self, ar=2, op=10):
		self.a = random.randint(ar, op)

	def gcd_(self, a, b):
		if a < b:
			return gcd(b, a)
		elif a % b == 0:
			return b
		else:
			return gcd(b, a % b)
		
	def gen_key(self, q):
		key = random.randint(pow(10, 20), q)
		while self.gcd_(q, key) != 1:
			key = random.randint(pow(10, 20), q)
		return key
	
	def power(self, a, b, c):
		x = 1
		y = a
		while b > 0:
			if b % 2 != 0:
				x = (x * y) % c
			y = (y * y) % c
			b = int(b / 2)
		return x % c
	
	def encrypt(self, plain_text):
		'''
		Encrypt the plain text using the Elliptic Curve Cryptography

		args:
			plain_text (str, int, float): text you want to encrypt
		
		returns:
			cipher_text (list): crypted text
			public_key (list): the public key for encryption and decryption
			key_receptor (int): the key needed by the receptor generated to decrypt this cipher_text 
		'''
		q = random.randint(pow(10, 20), pow(10, 50))
		g = random.randint(2, q)
		print(f'original text: {plain_text}')
		key_receptor = self.gen_key(q) 
		h = self.power(g, key_receptor, q) 

		cipher_text = []
	
		key_sender = self.gen_key(q)
		s = self.power(h, key_sender, q)
		p = self.power(g, key_sender, q)
		
		for i in range(0, len(str(plain_text))):
			cipher_text.append(str(plain_text)[i])
	
		print(f'private key (sender): {key_sender}')
		print(f'private key (receptor): {key_receptor}')
		for i in range(0, len(cipher_text)):
			cipher_text[i] = s * ord(cipher_text[i])

		public_key = [p, q]
		print(f'public key = {public_key}')
	
		return cipher_text, public_key, key_receptor

	def decrypt(self, cipher_text, public_key, key_receptor):
		'''
		Decrypt the text that were encrypted using a certain known public key

		args:
			cipher_text (list): the text that is encrypted
			public_key (list): the public key generated in the encrypt process of this cipher_text
			key_receptor (int): your private key
		
		returns:
			plain_text (str, int, float): original text
		'''
		dr_msg = []
		h = self.power(public_key[0], key_receptor, public_key[1])
          
		for i in range(0, len(cipher_text)):
			dr_msg.append(chr(int(cipher_text[i]/h)))
		plain_text = ''.join(dr_msg)
          
		return plain_text
