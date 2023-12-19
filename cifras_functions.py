import numpy as np

'''
Criptografia clássica: Dois tipos principais de cifra abrangeram a história da criptografia clássica: as cifras de substituição e as
de transposição. Nas cifras de substituição os símbolos do alfabeto do texto plano são substituídos por um ou mais símbolos do 
alfabeto do texto cifrado de acordo com uma regra, gerando o texto cifrado. Já nas cifras de transposição os símbolos do alfabeto do 
texto plano são permutados, também de acordo com uma regra, gerando o texto cifrado.
'''

# Cifra de César
# Altera a letra do alfabeto pulando n letras da sequencia
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifra-de-césar

@staticmethod
def cesar(texto, s=13):
    resultado = ""

    # Passa pelo texto
    for i in range(len(texto)):
        char = texto[i]

        # Encriptografa caracteres maiusculos
        if char.isupper():
            resultado += chr((ord(char) + s - 65) % 26 + 65)

        # Encriptografa caracteres minúsculos
        elif char.islower():
            resultado += chr((ord(char) + s - 97) % 26 + 97)
            
        # Encrpiptografa caracteres especiais
        else:
            if ord(char) >= 98:
                resultado += chr(ord(char)+ s)
            
            elif ord(char) <= 64:
                resultado += chr((ord(char)+ s) % 65)
            
            elif ord(char) >= 91 and ord(char) <=96 :
                resultado += chr((ord(char)+ s - 91) % 6 + 91)

    return resultado

@staticmethod
def de_cesar(texto, s=13):
    resultado = ""

    # Passa pelo texto
    for i in range(len(texto)):
        char = texto[i]

        # Descriptografa caracteres maiusculos
        if char.isupper():
            resultado += chr((ord(char) - s - 65) % 26 + 65)

        # Descriptografa caracteres minusculo
        if char.islower():
            resultado += chr((ord(char) - s - 97) % 26 + 97)

        # Descrpiptografa caracteres especiais
        else:
            if ord(char) >= 98:
                resultado += chr(ord(char)- s)
            
            elif ord(char) <= 64:
                resultado += chr((ord(char)- s) % 65)
            
            elif ord(char) >= 91 and ord(char) <=96 :
                resultado += chr((ord(char)- s - 91) % 6 + 91)

    return resultado

# Cifra atbash
# Inverte o alfabeto, começando com Z e terminando com A.
# Problemas conhecidos: acentos e alguns caracteres levam a resultados negativos, saindo da tabela ASCII
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifras-de-substituição-simples

@staticmethod
def atbash(texto):
    resultado = ""

    for i in range(len(texto)):
        char = texto[i]

        if char.isupper():
            resultado += chr(65 + 90 - ord(char))

        else:
            resultado += chr(97 + 122 - ord(char))

    return resultado

@staticmethod
def de_atbash(texto_cifrado):
    resultado = ""

    for i in range(len(texto_cifrado)):
        char = texto_cifrado[i]

        if char.isupper():
            resultado += chr(65 + 90 - ord(char))

        else:
            resultado += chr(97 + 122 - ord(char))

    return resultado

# Cifra de Transposição
# A mensagem é escrita horizontalmente numa matriz de largura fixa e a saída é o texto lido verticalmente nessa matriz. Numa transposição colunar simples essa leitura é feita pelas colunas da esquerda para direita
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifras-de-transposição

@staticmethod
def transpColumn(texto, key='abc'):
    cifrado=""
    b=''
    n=len(key)
    aux=int(len(texto)/n + 1)
    aux= aux, n
    Matriz = np.zeros(aux)
    count=0
    countkey=1
    auxkey= 1, n
    keyaux= np.zeros(auxkey)

    for i in range(aux[0]):
        for j in range(n):
            if count < len(texto):
                Matriz[i][j]=ord(texto[count])
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
                cifrado += chr(int(aux2[j]))

    return cifrado

@staticmethod
def de_transpColumn(texto, key='abc'):
    cifrado=""
    n=len(key)
    aux=int(len(texto)/n + 1)
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
            if j == aux[0]-1 and c>len(texto) % n -1:
                continue
            if count < len(texto):
                c = int(keyaux[0][i])
                Matriz[j][c]=ord(texto[count])
                count +=1
    
    for i in range(aux[0]):
        aux2=Matriz[i,:]
        for j in range(len(aux2)):
            if int(aux2[j])!=0:
                cifrado += chr(int(aux2[j]))
    
    return cifrado

# Cifra de Vigenère
# É uma cifra polialfabetica que consiste basicamente em pegar uma palavra-chave e aplicar a cifra de César várias vezes, de acordo com os caracteres da palavra-chave.
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifra-de-vigenère

@staticmethod
def vigenere(texto, chave='demar'):
    cifrado=""
    numchave=[]
    count=0

    for i in range(len(chave)):
        if chave[i].isupper() == True:
            numchave.append(ord(chave[i])-ord('A'))
        else:
            numchave.append(ord(chave[i])-ord('a'))
    for i in range(len(texto)):
        aux=count%len(chave)
        char = cesar(texto[i],numchave[aux])
        count +=1
        cifrado += char
    return cifrado

@staticmethod
def de_vigenere(texto, chave='demar'):
    cifrado=''
    numchave=[]
    count=0

    for i in range(len(chave)):
        if chave[i].isupper() == True:
            numchave.append(ord(chave[i])-ord('A'))
        else:
            numchave.append(ord(chave[i])-ord('a'))
    for i in range(len(texto)):
        aux=count%len(chave)
        char = de_cesar(texto[i],numchave[aux])
        count +=1
        cifrado += char

    return cifrado

'''
#Exemplo de Criptografia clássica:
og='Hello World'
cesr=cesar(og,3)
atbas=atbash(og)
TranC= transpColumn(og, "demar")
vig=vigenere(og)

print('==============================================================')
print(f'\033[35;1mKey:\033[m demar')
print(f'\033[36;1mTexto Original:\033[m {og}')
print(f'\033[35;1mTexto Criptogrado com César (n=3):\033[m {cesr}')
print(f'\033[35;1mTexto Criptogrado com AtBash:\033[m {atbas}')
print(f'\033[35;1mTexto Criptogrado com Transposição de Coluna:\033[m {TranC}')
print(f'\033[35;1mTexto Criptogrado com Vigenère:\033[m {vig}')
print(f'\033[36;1mTexto Descriptogrado com César:\033[m {de_cesar(cesr,3)}')
print(f'\033[36;1mTexto Descriptogrado com AtBash:\033[m {de_atbash(atbas)}')
print(f'\033[36;1mTexto Descriptogrado com Transposição de Coluna:\033[m {de_transpColumn(TranC,"demar")}')
print(f'\033[36;1mTexto Descriptogrado com Vigenère:\033[m {de_vigenere(vig)}')
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
        plaintext=bytes(plaintext, encoding)
    
    if isinstance(key, bytes) == False:
        key=bytes(key, encoding)
    
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
texto = b'Hello World!'
chave = b'demar'

print('==============================================================')
print(f'\033[35;1mKey em bytes:\033[m {chave}')
print(f'\033[36;1mBytes Original:\033[m {texto}')
print(f"\033[35;1mBytes Criptogrado com OneTimePad:\033[m {onetimepad(texto, chave)}")
print(f"\033[36;1mBytes Descriptogrado com OneTimePad:\033[m {de_onetimepad(onetimepad(texto, chave), chave)}")
print('==============================================================')
'''