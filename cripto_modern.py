import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
import random 
from math import pow, gcd

class AESCipher(object):
    '''
    Can cript/decript using Advanced Encryption Standart

    object (str): a secret key to hide/reveal an information 
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
	
	def encrypt(self, msg, q, h, g):
	
		en_msg = []
	
		key_sender = self.gen_key(q)
		s = self.power(h, key_sender, q)
		p = self.power(g, key_sender, q)
		
		for i in range(0, len(str(msg))):
			en_msg.append(str(msg)[i])
	
		for i in range(0, len(en_msg)):
			en_msg[i] = s * ord(en_msg[i])
	
		return en_msg, p

	def decrypt(self, en_msg, p, key_reciever, q):
	
		dr_msg = []
		h = self.power(p, key_reciever, q)

		for i in range(0, len(en_msg)):
			dr_msg.append(chr(int(en_msg[i]/h)))
			
		return dr_msg

	def ElGamal(self, plain_text): # dar uma olhada assim que possível: separar encrypt de decrypt? q, g, etc tem que ser os mesmos!
		'''
		Encrypt or decript the plain text using the Elliptic Curve Cryptography
		
		args:
            msg (str, int, float): text you want to either encrypt or decript
		
		returns: 
            en_msg: cipher text after encryption
			dmsg (str, int, float): orinal text after decryption
		'''
		q = random.randint(pow(10, 20), pow(10, 50))
		g = random.randint(2, q)
		key_reciever = self.gen_key(q)
		h = self.power(g, key_reciever, q)

		en_msg, p = self.encrypt(plain_text, q, h, g)
		
		dr_msg = self.decrypt(en_msg, p, key_reciever, q)
		dmsg = ''.join(dr_msg)

		return en_msg, dmsg

'''
How to use:
crypted_in_AES = AESChiper(key).encrypt(plain_text)

decrypted_in_AES = AESChiper(key).decrypt(chiper_text)

using_ECC = ECCChiper.ElGamal(plain_text)
'''
