import cifras_functions as cifra

# cipher_archive cria um arquivo com os conteúdos criptogrados com base em uma cifra de criptografia clássica
# Como a natureza das cifras é de informação do Unicode, é implementado apenas para arquivos .txt
def cipher_archive(key, full_path=str, method='cesar', name='ciphertext'):
    """
    Cria um arquivo com os conteúdos textuais de outro arquivo cifrados.
    As cifras implementadas funcionam em codificação utf-8 e são Cesar, Atbash, Transposição de Coluna e Vigenere.
    """
    
    valid = {'cesar', 'atbash', 'tcolumn', 'vigenere'}
    if method not in valid:
        raise ValueError("Error: method must be one of %r." % valid)
    
    iterator = full_path.find('.', -4)
    if iterator != -1:
        suffix = full_path[iterator:]
        name += suffix
    
    with open(full_path, 'rt') as file:
        plaintext= file.read()

    if method == 'cesar':
        if isinstance(key, int) == True:
            ciphertext = cifra.cesar(plaintext, key)
        else:
            raise TypeError("Error: key must be a integer for cesar.")
    
    if method == 'atbash':
        ciphertext = cifra.atbash(plaintext)

    if method == 'TColumn':
        if isinstance(key, str) == True:
            ciphertext = cifra.transpColumn(plaintext, key)
        else:
            raise TypeError("Error: key must be a string for Column Transposition.")

    if method == 'vigenere':
        if isinstance(key, str) == True:
            ciphertext = cifra.vigenere(plaintext, key)
        else:
            raise TypeError("Error: key must be a string Vigenere.")

    try:
        with open(name, 'xt') as cipherfile:
            cipherfile.write(ciphertext)
        print(f"File created.\nThe key is {key}, don't lose it")
    except FileExistsError:
        print('File already exists.')
    
    return

# decipher_archive cria um arquivo com os conteúdos descriptogrados com base em uma cifra de criptografia clássica e uma chave
# Como a natureza das cifras é de informação do Unicode, é implementado apenas para arquivos .txt
def decipher_archive(key, full_path=str, method='cesar', name='plaintext'):
    """
    Cria um arquivo com os conteúdos textuais de outro arquivo decifrados.
    As cifras implementadas funcionam em codificação utf-8 e são Cesar, Atbash, Transposição de Coluna e Vigenere.
    """

    valid = {'cesar', 'atbash', 'tcolumn', 'vigenere'}
    if method not in valid:
        raise ValueError("Error: method must be one of %r." % valid)
    
    iterator = full_path.find('.', -4)
    if iterator != -1:
        suffix = full_path[iterator:]
        name += suffix
    
    with open(full_path, 'rt') as file:
        ciphertext= file.read()

    if method == 'cesar':
        if isinstance(key, int) == True:
            plaintext = cifra.de_cesar(ciphertext, key)
        else:
            raise TypeError("Error: key must be a integer for cesar.")
    
    if method == 'atbash':
        plaintext = cifra.de_atbash(ciphertext)

    if method == 'TColumn':
        if isinstance(key, str) == True:
            plaintext = cifra.de_transpColumn(ciphertext, key)
        else:
            raise TypeError("Error: key must be a string for Column Transposition.")

    if method == 'vigenere':
        if isinstance(key, str) == True:
            plaintext = cifra.de_vigenere(ciphertext, key)
        else:
            raise TypeError("Error: key must be a string for Vigenere.")

    try:
        with open(name, 'xt') as plainfile:
            plainfile.write(plaintext)
        print(f"File created.\nThe key used was {key}")
    except FileExistsError:
        print('File already exists.')
    
    return

# encrypt_archive cria um arquivo criptogrado com base em um algoritmo de criptografia moderna e uma chave relacionada
def encrypt_archive(key, full_path=str, method='OTP', name='encryptdata', encoding='utf-8'):
    """
    Cria um arquivo com as informações de outro arquivo criptografadas.
    Os algoritmos implementados funcionam alterando bytes e o arquivo criptografado pode não ser possível de abrir.
    Os algoritmos são OneTimePad.
    """
    
    valid = {'OTP', 'AES', 'EEC'}
    if method not in valid:
        raise ValueError("Error: method must be one of %r." % valid)

    iterator = full_path.find('.', -4)
    if iterator != -1:
        suffix = full_path[iterator:]
        name += suffix
    
    if isinstance(key, bytes) == False:
        if isinstance(key, str) == True:
            key=bytes(key, encoding)
        else:
            key=bytes(str(key), encoding)
    
    with open(full_path, 'rb') as file:
        plaindata= file.read()

    if method == 'OTP':
        encryptdata = cifra.onetimepad(plaindata, key, encoding)

    #if method == '':

    try:
        with open(name, 'xb') as encryptfile:
            encryptfile.write(encryptdata)
        print(f"File created.\nThe key is {key}, don't lose it")
    except FileExistsError:
        print('File already exists.')

    return

# decrypt_archive cria um arquivo descriptogrado com base em um algoritmo de criptografia moderna e uma chave relacionada
def decrypt_archive(key, full_path=str, method='OTP', name='plaindata', encoding='utf-8'):
    """
    Cria um arquivo com as informações de outro arquivo descriptografadas.
    Os algoritmos são OneTimePad.
    """
    
    valid = {'OTP', 'AES', 'EEC'}
    if method not in valid:
        raise ValueError("Error: method must be one of %r." % valid)

    iterator = full_path.find('.', -4)
    if iterator != -1:
        suffix = full_path[iterator:]
        name += suffix

    if isinstance(key, bytes) == False:
        if isinstance(key, str) == True:
            key=bytes(key, encoding)
        else:
            key=bytes(str(key), encoding)
    
    with open(full_path, 'rb') as file:
        encryptdata= file.read()
    
    if method == 'OTP':
        plaindata = cifra.de_onetimepad(encryptdata, key, encoding)
    
    #if method == '':

    try:
        with open(name, 'xb') as plainfile:
            plainfile.write(plaindata)
        print(f"File created.\nThe key used was {key}")
    except FileExistsError:
        print('File already exists.')

    return