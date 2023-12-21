##### Criptografia/Descriptografia Simétrica usando Algorítimos Modernos ######
'''
### Criptografia Simétrica
# AES (Advanced Encryption Standard):

	Usa tamanhos de chave de 128, 192 ou 256 bits, tornando-o muito mais seguro do que o DES. Usa uma série de operações de substitui-
	 ção, permutação e mistura (chamadas de SubBytes, ShiftRows e MixColumns) que são aplicadas repetidamente com base na chave.

	O processo de criptografia do AES é altamente seguro devido ao tamanho da chave e ao número de rounds (10, 12 ou 14, dependendo do
	 tamanho da chave) que são aplicados.

'''

import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode

### AES (implementação)

'''
Fonte: https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2

"data should not only be stored in a secure environment, it should also be encrypted with a a secure algorithm, such as AES."
'''

class AESCipher(object):

    def __init__(self, key):
        '''
        Recebe uma key de qualquer tamanho e gera um hash*¹ único de 256 bits dessa key

        *¹ O que é um Hash? 
            Função matemática que converte um arquivo de qualquer tamanho em um código de letras e números de tamanho fixo.
            É como se fosse uma impressão digital do arquivo.
        '''
        self.block_size = AES.block_size # tamanho de um bloco de dados em bytes (128)
        self.key = hashlib.sha256(key.encode()).digest() 

    def __pad(self, plain_text):
        '''
        Esse método recebe o plain_text para ser codificado e adiciona um número de bytes para texto de tal forma que este
        seja um múltiplo de 128. (number_of_bytes_to_pad)
        ascii_string vai gerar esse "caractere de preenchimento"  e então adicionando padding_str ao fim do texto, tempos 
        o múltiplo que era necessário.
        '''
        number_of_bytes_to_pad = self.block_size - len(str(plain_text)) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = str(plain_text) + padding_str
        return padded_plain_text


    @staticmethod
    def __unpad(plain_text):
        '''
        Contrariamente ao método __pad, identifica esse último caractere do __pad e armazena em bytrse_to_remove para 
        remove-los do plain_text
        '''
        last_character = plain_text[len(str(plain_text)) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]

    def encrypt(self, plain_text):
        '''
        Recebe o plain_text para criptografar em AES. Primeiro, é usado o método __pad pra o programa ser capaz de encriptografar
        dado os block_size do algorítimo. 
        Então é gerado um iv aleatório com o tamanho de um bloco AES (128 bits).
        Agora, em cipher, é criado a Cífra com a chave, modo CBC*2 e o iv gerado e plain_text é convertido para bits
        O arquivo (originalmente plain_text) é criptografado e gerado/colocado na frente do iv e convertido de volta (caracteres).

        *² O que é o modo CBC?
            CBC significa "Cipher-Block Chaining": é um modo de operação para uma cifra de bloco, em que uma sequência de
             bits é criptografada como uma unidade, ou bloco, com uma chave de cifra (key) aplicada a todo o bloco. O CBC usa o
             que é conhecido como vetor de inicialização (IV) de um determinado comprimento. Ao usar isso junto com uma única 
             key, é possível criptografar/descriptografar com segurança grandes quantidades de texto simples.
        '''
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        '''
        Basicamente, volta todos os passos da função encrypt. Ao final, removemos o __pad usando o __unpad
        '''
        try:
            encrypted_text = b64decode(encrypted_text)
        except:
            raise Exception("Can't decode this information.")
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

'''
Próximos passos em AES:
arquivos - https://medium.com/quick-code/understanding-the-advanced-encryption-standard-7d7884277e7
sem pycrypto - ???
'''

if __name__ == '__main__':
    # AES teste:

    chave = 'Yy3W5Xs4SwDXrMsF19nwwq'
    mensagem = 2452.62365

    aes1 = AESCipher(chave)
    crpt = aes1.encrypt(mensagem)
    Icrpt = aes1.decrypt(crpt)
    print('-=-'*10)
    print(f'Key: {chave}')
    print(f'\033[34;1mMensagem clara:\033[m {mensagem}')
    print(f'\033[35;1mMensagem criptografada com AES:\033[m {crpt}')
    print(f'\033[36;1mMensagem após descriptografia:\033[m {Icrpt}')
    print('-=-'*10)
    crpt2 = AESCipher(chave).encrypt(mensagem)
    print(crpt2)
    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-
