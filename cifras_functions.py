import numpy as np

'''
Criptografia clássica: Dois tipos principais de cifra abrangeram a história da criptografia clássica: as cifras de substituição e as
de transposição. Nas cifras de substituição os símbolos do alfabeto do plaintext plano são substituídos por um ou mais símbolos do 
alfabeto do plaintext ciphertext de acordo com uma regra, gerando o plaintext ciphertext. Já nas cifras de transposição os símbolos do alfabeto do 
plaintext plano são permutados, também de acordo com uma regra, gerando o plaintext ciphertext.
'''

# Cifra de César
# Altera a letra do alfabeto pulando n letras da sequencia
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifra-de-césar

@staticmethod
def cesar(plaintext, s=13):
    ciphertext = ""

    # Passa pelo plaintext
    for i in range(len(plaintext)):
        char = plaintext[i]

        # Encriptografa caracteres maiusculos
        if char.isupper():
            ciphertext += chr((ord(char) + s - 65) % 26 + 65)

        # Encriptografa caracteres minúsculos
        elif char.islower():
            ciphertext += chr((ord(char) + s - 97) % 26 + 97)
            
        # Encrpiptografa caracteres especiais
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
    plaintext = ""

    # Passa pelo ciphertext
    for i in range(len(ciphertext)):
        char = ciphertext[i]

        # Descriptografa caracteres maiusculos
        if char.isupper():
            plaintext += chr((ord(char) - s - 65) % 26 + 65)

        # Descriptografa caracteres minusculo
        if char.islower():
            plaintext += chr((ord(char) - s - 97) % 26 + 97)

        # Descrpiptografa caracteres especiais
        else:
            if ord(char) >= 98:
                plaintext += chr(ord(char)- s)
            
            elif ord(char) <= 64:
                plaintext += chr((ord(char)- s) % 65)
            
            elif ord(char) >= 91 and ord(char) <=96 :
                plaintext += chr((ord(char)- s - 91) % 6 + 91)

    return plaintext

# Cifra atbash
# Inverte o alfabeto, começando com Z e terminando com A.
# Problemas conhecidos: acentos e alguns caracteres levam a resultados negativos, saindo da tabela ASCII
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifras-de-substituição-simples

@staticmethod
def atbash(plaintext):
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
    plaintext = ""

    for i in range(len(ciphertext)):
        char = ciphertext[i]

        if char.isupper():
            plaintext += chr(65 + 90 - ord(char))

        else:
            plaintext += chr(97 + 122 - ord(char))

    return plaintext

# Cifra de Transposição
# A mensagem é escrita horizontalmente numa matriz de largura fixa e a saída é o plaintext lido verticalmente nessa matriz. Numa transposição colunar simples essa leitura é feita pelas colunas da esquerda para direita
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifras-de-transposição

@staticmethod
def transpColumn(plaintext, key='abc'):
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
def de_transpColumn(plaintext, key='abc'):
    ciphertext=""
    n=len(key)
    aux=int(len(plaintext)/n + 1)
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
            if j == aux[0]-1 and c>len(plaintext) % n -1:
                continue
            if count < len(plaintext):
                c = int(keyaux[0][i])
                Matriz[j][c]=ord(plaintext[count])
                count +=1
    
    for i in range(aux[0]):
        aux2=Matriz[i,:]
        for j in range(len(aux2)):
            if int(aux2[j])!=0:
                ciphertext += chr(int(aux2[j]))
    
    return ciphertext

# Cifra de Vigenère
# É uma cifra polialfabetica que consiste basicamente em pegar uma palavra-chave e aplicar a cifra de César várias vezes, de acordo com os caracteres da palavra-chave.
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifra-de-vigenère

@staticmethod
def vigenere(plaintext, chave='demar'):
    ciphertext=""
    numchave=[]
    count=0

    for i in range(len(chave)):
        if chave[i].isupper() == True:
            numchave.append(ord(chave[i])-ord('A'))
        else:
            numchave.append(ord(chave[i])-ord('a'))
    for i in range(len(plaintext)):
        aux=count%len(chave)
        char = cesar(plaintext[i],numchave[aux])
        count +=1
        ciphertext += char
    return ciphertext

@staticmethod
def de_vigenere(plaintext, chave='demar'):
    ciphertext=''
    numchave=[]
    count=0

    for i in range(len(chave)):
        if chave[i].isupper() == True:
            numchave.append(ord(chave[i])-ord('A'))
        else:
            numchave.append(ord(chave[i])-ord('a'))
    for i in range(len(plaintext)):
        aux=count%len(chave)
        char = de_cesar(plaintext[i],numchave[aux])
        count +=1
        ciphertext += char

    return ciphertext

'''
#Exemplo de Criptografia clássica:
og='Hello World!'
cesr=cesar(og,3)
atbas=atbash(og)
TranC= transpColumn(og, "demar")
vig=vigenere(og)

print('==============================================================')
print(f'\033[35;1mKey:\033[m demar')
print(f'\033[36;1mplaintext Original:\033[m {og}')
print(f'\033[35;1mplaintext Criptogrado com César (key = 3):\033[m {cesr}')
print(f'\033[35;1mplaintext Criptogrado com AtBash:\033[m {atbas}')
print(f'\033[35;1mplaintext Criptogrado com Transposição de Coluna:\033[m {TranC}')
print(f'\033[35;1mplaintext Criptogrado com Vigenère:\033[m {vig}')
print(f'\033[36;1mplaintext Descriptogrado com César:\033[m {de_cesar(cesr,3)}')
print(f'\033[36;1mplaintext Descriptogrado com AtBash:\033[m {de_atbash(atbas)}')
print(f'\033[36;1mplaintext Descriptogrado com Transposição de Coluna:\033[m {de_transpColumn(TranC,"demar")}')
print(f'\033[36;1mplaintext Descriptogrado com Vigenère:\033[m {de_vigenere(vig)}')
print('==============================================================')
'''
'''
Com a entrada da computação no cenário e a chegada da era moderna, a criptografia expandiu seus campos de atuação, de modo que hoje
lidamos com sequencias de bits, que podem significar letras, pixels de uma imagem, áudios, entre outros. Logo, a Criptografia Moderna
trata da segurança da informação que essas sequencias de bits carregam.
'''
# One time pad
# Utiliza da operação XOR , bit a bit, com uma chave para obter uma mensagem criptografada. A funcao foi definida tendo em mente informacao
# em modelos de bytes
@staticmethod
def onetimepad(plaintext, key, encoding='utf-8'):
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
    return onetimepad(ciphertext, key, encoding)

'''
#Exemplo de Criptografia moderna:
plaintext = b'Hello World!'
chave = b'demar'

print('==============================================================')
print(f'\033[35;1mKey em bytes:\033[m {chave}')
print(f'\033[36;1mBytes Original:\033[m {plaintext}')
print(f"\033[35;1mBytes Criptogrado com OneTimePad:\033[m {onetimepad(plaintext, chave)}")
print(f"\033[36;1mBytes Descriptogrado com OneTimePad:\033[m {de_onetimepad(onetimepad(plaintext, chave), chave)}")
print('==============================================================')
'''