##### Criptografia/Descriptografia Assimétrica usando Algorítimos Modernos ######
'''
### Criptografia Assimétrica
# ECC (Elliptic Curve Cryptography): NORMALMENTE USADA PARA ASSINATURA DIGITAL!!!!!

	A ECC é baseada em operações matemáticas envolvendo curvas elípticas sobre campos finitos.

	A chave pública em ECC é gerada como um ponto na curva elíptica e a chave privada é um número inteiro.

	A segurança da ECC baseia-se no problema do logaritmo discreto em uma curva elíptica, que é considerado mais difícil de resolver em
	 comparação com problemas semelhantes em outros campos. A ECC oferece uma segurança equivalente ao RSA com chaves muito menores, 
	 tornando-a uma escolha atraente para dispositivos com recursos limitados.

Criptografia Direta: El Gamal
	Bob generates public and private keys: 
	Bob chooses a very large number q and a cyclic group Fq.
	From the cyclic group Fq, he choose any element g and
	an element a such that gcd(a, q) = 1.
	Then he computes h = ga.
	Bob publishes F, h = ga, q, and g as his public key and retains a as private key.
Alice encrypts data using Bob's public key : 
	Alice selects an element k from cyclic group F 
	such that gcd(k, q) = 1.
	Then she computes p = gk and s = hk = gak.
	She multiples s with M.
	Then she sends (p, M*s) = (gk, M*s).
Bob decrypts the message : 
	Bob calculates s' = pa = gak.
	He divides M*s by s' to obtain M as s = s'.
'''

from fastecdsa import keys, curve,ecdsa
import random 
from math import pow, gcd

### ECC (implementação)

'''
Fonte:
https://medium.com/@schaetzcornelius/learn-how-to-code-elliptic-curve-cryptography-be646d2c9757
https://www.geeksforgeeks.org/elgamal-encryption-algorithm/
https://www.geeksforgeeks.org/blockchain-elliptic-curve-cryptography/ 
'''


# ---------------===============----------------=================--------------------========---------------
# Aqui é a aplicação para assinatura digital
priv_key, pub_key = keys.gen_keypair(curve.P256)

message = 'Method KISS slaps'
(r,s) = ecdsa.sign(message,priv_key) # gera uma assinatura (r, s) com a chave privada

valid = ecdsa.verify((r,s),message,pub_key) # Verifica se a assinatura corresponde à chave pública (sem acessar a chave privada)
if valid == True:
	print(f'\033[1;32m{valid}\033[m')
if not valid == True:
	raise Exception('A chave privada não pertence ao usuário dessa chave pública!')
print('-=-' * 20)
# ---------------===============-----------------================-----------------=============-------------

# Criptografia direta usando El Gamal
class ECCCipher(object):

	def __init__(self, ar=2, op=10):
		self.a = random.randint(ar, op)

	def gcd_(self, a, b):
		'''
		Processo descrito no comentário do topo
		'''
		if a < b:
			return gcd(b, a)
		elif a % b == 0:
			return b
		else:
			return gcd(b, a % b)
		
	# gerando números grandes e aleatórios
	def gen_key(self, q):
		key = random.randint(pow(10, 20), q)
		while self.gcd_(q, key) != 1:
			key = random.randint(pow(10, 20), q)
		return key
	
	def power(self, a, b, c):
		'''
		Processo descrito no comentário do topo
		'''
		x = 1
		y = a
		while b > 0:
			if b % 2 != 0:
				x = (x * y) % c
			y = (y * y) % c
			b = int(b / 2)
		return x % c
	
	def encrypt(self, msg): # (q, g, h) --> public key 
		
		q = random.randint(pow(10, 20), pow(10, 50))
		g = random.randint(2, q)
		print(f'original text: {msg}')
		#print(f'q used = {q}')
		#print(f'g used = {g}')
		key = self.gen_key(q) # chave privada para quem recebe
		h = self.power(g, key, q) # g^a
		#print(f'g^a (h) used = {h}')


		en_msg = []
	
		k = self.gen_key(q) # chave privada para quem envia
		s = self.power(h, k, q)
		p = self.power(g, k, q)
		
		for i in range(0, len(str(msg))):
			en_msg.append(str(msg)[i])
	
		#print("g^k (p) used =", p)
		#print("g^ak (s) used =", s)
		print(f'private key (emissor): {k}')
		print(f'private key (receptor): {key}')
		for i in range(0, len(en_msg)):
			en_msg[i] = s * ord(en_msg[i])

		public_key = [p, q]
		print(f'public key = {public_key}')
	
		return en_msg, public_key, key

	def decrypt(self, en_msg, public_key, key):
	
		dr_msg = []
		h = self.power(public_key[0], key, public_key[1]) # p^a = g^(ak)
		for i in range(0, len(en_msg)):
			dr_msg.append(chr(int(en_msg[i]/h)))
		dmsg = ''.join(dr_msg)
		return dmsg

if __name__ == '__main__':
	# ECC tester
	mensagem = 1234.132124
	
	ecc1 = ECCCipher(2, 10)
	#ECCaply = ecc1.ElGamal(mensagem)
	encryption, public_key, key = ecc1.encrypt(mensagem)
	decryption = ecc1.decrypt(encryption, public_key, key)
	print('-=-'*20)
	print(f'mensagem descriptada: {decryption}')
	# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-
