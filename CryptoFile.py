import CryptoFunctions as cifra

def cipher_archive(key, full_path=str, method='cesar', name='ciphertext'):
    """
    Create a new file with the text content of a file ciphered

    The implemented ciphers are (coding utf-8):
        Cesar Cipher
        AtBash Cipher
        Columnar Transposition Cipher
        Vigenere Cipher

    args:
        key (): secret key
        full_path (str): path of the file to encrypt
        method (str): name of cipher to use
        name (str): name of the new file

    raises:
        ValueError("Error: method must be one of %r." % valid)
        TypeError("Error: key must be a integer for cesar.")
        TypeError("Error: key must be a string for Column Transposition.")
        TypeError("Error: key must be a string Vigenere.")
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

def decipher_archive(key, full_path=str, method='cesar', name='plaintext'):
    """
    Create a new file with the text content ciphered of a file

    The implemented ciphers are (coding utf-8):
        Cesar Cipher
        AtBash Cipher
        Columnar Transposition Cipher
        Vigenere Cipher

    args:
        key (): secret key
        full_path (str): path of the file to dencrypt
        method (str): name of cipher to use
        name (str): name of the new file

    raises:
        ValueError("Error: method must be one of %r." % valid)
        TypeError("Error: key must be a integer for cesar.")
        TypeError("Error: key must be a string for Column Transposition.")
        TypeError("Error: key must be a string Vigenere.")
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

def encrypt_archive(key, full_path=str, method='OTP', name='encryptdata', encoding='utf-8'):
    """
    Create a new file with the content of a file ciphered

    The implemented ciphers are (bytes):
        OneTimePad Cipher

    args:
        key (): secret key
        full_path (str): path of the file to encrypt
        method (str): name of cipher to use
        name (str): name of the new file
        encoding: utf-8 standart

    raises:
        ValueError("Error: method must be one of %r." % valid)
    """
    
    valid = {'OTP'}
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

    try:
        with open(name, 'xb') as encryptfile:
            encryptfile.write(encryptdata)
        print(f"File created.\nThe key is {key}, don't lose it")
    except FileExistsError:
        print('File already exists.')

    return

def decrypt_archive(key, full_path=str, method='OTP', name='plaindata', encoding='utf-8'):
    """
    Create a new file with the content ciphered of a file

    The implemented ciphers are (bytes):
        OneTimePad Cipher

    args:
        key (): secret key
        full_path (str): path of the file to dencrypt
        method (str): name of cipher to use
        name (str): name of the new file
        encoding: utf-8 standart

    raises:
        ValueError("Error: method must be one of %r." % valid)
    """
    
    valid = {'OTP'}
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

    try:
        with open(name, 'xb') as plainfile:
            plainfile.write(plaindata)
        print(f"File created.\nThe key used was {key}")
    except FileExistsError:
        print('File already exists.')

    return
