import numpy as np

# Ideias para próximos passos: implementar solucao por frequencia, bruteforce cesar, arrumar problemas

# Cifra de César
# Altera a letra do alfabeto pulando n letras da sequencia
# Problemas conhecidos: decriptografar caracteres especiais
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
        else:
            resultado += chr((ord(char) + s - 97) % 26 + 97)

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
        else:
            resultado += chr((ord(char) - s - 97) % 26 + 97)

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
# Problemas Conhecidos:
# implementar palavra chave (len define n, cada letra define a ordem das coluna)
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifras-de-transposição

@staticmethod
def transpColumn(texto, n=3):
    cifrado=""
    aux=int(len(texto)/n + 1)
    aux= aux, n
    Matriz = np.zeros(aux)
    count=0

    for i in range(aux[0]):
        for j in range(n):
            if count < len(texto):
                Matriz[i][j]=ord(texto[count])
                count +=1
    for i in range(n):
        aux2=Matriz[:,i]
        for j in range(len(aux2)):
            if int(aux2[j])!=0:
                cifrado += chr(int(aux2[j]))

    return cifrado

@staticmethod
def de_transpColumn(texto,n=3):
    cifrado=""
    aux=int(len(texto)/n + 1)
    aux= aux, n
    Matriz = np.zeros(aux)
    count=0
    
    for i in range(n):
        for j in range(aux[0]):
            if count < len(texto):
                Matriz[j][i]=ord(texto[count])
                count +=1
    for i in range(aux[0]):
        aux2=Matriz[i,:]
        for j in range(len(aux2)):
            if int(aux2[j])!=0:
                cifrado += chr(int(aux2[j]))

    return cifrado

# Cifra de Vigenère
# É uma cifra polialfabetica que consiste basicamente em pegar uma palavra-chave e aplicar a cifra de César várias vezes, de acordo com os caracteres da palavra-chave.
# Problemas conhecidos: Caracteres especiais devido a heredietaridade com Cesar
# Fonte: https://wiki.imesec.ime.usp.br/books/criptografia/page/cifra-de-vigenère

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
