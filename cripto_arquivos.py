import random
import cifras_functions as cifra

# cipher_archive cria um arquivo com os conteúdos criptogrados com base em uma cifra de criptografia clássica
# Como a natureza das cifras é de informação do Unicode, é implementado apenas para arquivos .txt
def cipher_archive(full_path, key, mode='cesar', name='ciphertext'):
    
    valid = {'cesar', 'atbash', 'tcolumn', 'vigenere'}
    if mode not in valid:
        raise ValueError("Error: mode must be one of %r." % valid)
    
    with open(full_path, 'rt') as file:
        plaintext= file.read()

    if mode == 'cesar':
        if isinstance(key, int) == True:
            ciphertext = cifra.cesar(plaintext, key)
        else:
            raise ValueError("Error: key must be a integer for cesar.")
    
    if mode == 'atbash':
        ciphertext = cifra.atbash(plaintext)

    if mode == 'TColumn':
        if isinstance(key, str) == True:
            ciphertext = cifra.transpColumn(plaintext, key)
        else:
            raise ValueError("Error: key must be a string for Column Transposition.")

    if mode == 'vigenere':
        if isinstance(key, str) == True:
            ciphertext = cifra.vigenere(plaintext, key)
        else:
            raise ValueError("Error: key must be a string Vigenere.")

    try:
        with open(name, 'xt') as cipherfile:
            cipherfile.write(ciphertext)
        print(f"File created.\nThe key is {key}")
    except FileExistsError:
        print('File already exists.')
    
    return

# decipher_archive cria um arquivo com os conteúdos descriptogrados com base em uma cifra de criptografia clássica e uma chave
# Como a natureza das cifras é de informação do Unicode, é implementado apenas para arquivos .txt
def decipher_archive(full_path, key, mode='cesar', name='plaintext'):

    valid = {'cesar', 'atbash', 'tcolumn', 'vigenere'}
    if mode not in valid:
        raise ValueError("Error: mode must be one of %r." % valid)
    
    with open(full_path, 'rt') as file:
        ciphertext= file.read()

    if mode == 'cesar':
        if isinstance(key, int) == True:
            plaintext = cifra.de_cesar(ciphertext, key)
        else:
            raise ValueError("Error: key must be a integer for cesar.")
    
    if mode == 'atbash':
        plaintext = cifra.de_atbash(ciphertext)

    if mode == 'TColumn':
        if isinstance(key, str) == True:
            plaintext = cifra.de_transpColumn(ciphertext, key)
        else:
            raise ValueError("Error: key must be a string for Column Transposition.")

    if mode == 'vigenere':
        if isinstance(key, str) == True:
            plaintext = cifra.de_vigenere(ciphertext, key)
        else:
            raise ValueError("Error: key must be a string Vigenere.")

    try:
        with open(name, 'xt') as plainfile:
            plainfile.write(plaintext)
        print(f"File created.\nThe key is {key}")
    except FileExistsError:
        print('File already exists.')
    
    return

'''
path = r"C:\Users\enzob\OneDrive\Área de Trabalho\teste.txt"
cipher_archive(path, 1)
path2 =r"C:\Users\enzob\Projeto_Computacional-grupo_2\ciphertext"
decipher_archive(path2, 1)

# encrypt_archive cria um arquivo criptogrado com base em um algoritmo de criptografia moderna e uma chave relacionada
def encrypt_archive(full_path, key, mode='OTP', encoding='utf-8'):
     if isinstance(key, bytes) == False:
        key=bytes(key, encoding)
     
     print(f"The key is {key}")
     return

# decrypt_archive cria um arquivo descriptogrado com base em um algoritmo de criptografia moderna e uma chave relacionada
def decrypt_archive(full_path, key, mode='OTP', encoding='utf-8'):
    if isinstance(key, bytes) == False:
        key=bytes(key, encoding)
    
    return\
'''