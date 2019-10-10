#!/usr/bin/env python3

import base64, os, argparse, sys
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def main():
    '''
    File/string encrytpion/decryption script.  Uses Fernet symmetric key encryption algorithm.
    128-bit AES in CBC mode.  HMAC is SHA256 with 16 bit salt.
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('-g','--genkey',action='store_true',dest='genkey',help='Generate new random key')
    parser.add_argument('-p','--passwd',action='store',dest='passwd',help='Use password based key')
    parser.add_argument('-e','--encrypt',action='store',dest='encr',help='Encrypt this file or string')
    parser.add_argument('-d','--decrypt',action='store',dest='decr',help='Decrypt this file or string')
    parser.add_argument('-k','--key',action='store',dest='key',help='Use this key')

    args = parser.parse_args()
    '''
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    b_prefix = "["+RED+"FAIL"+ENDC+"] "
    g_prefix = "["+GREEN+" OK "+ENDC+"] "
    n_prefix = "["+YELLOW+" ** "+ENDC+"] "
    '''
    
    try:
        import colorama
        from colorama import Fore, Style
        colorama.init()
        b_prefix = "["+Fore.RED+"FAIL"+Style.RESET_ALL+"] "
        g_prefix = "["+Fore.GREEN+" OK "+Style.RESET_ALL+"] "
        n_prefix = "["+Fore.YELLOW+" ** "+Style.RESET_ALL+"] "
    except ImportError:
        b_prefix = "[FAIL] "
        g_prefix = "[ OK ] "
        n_prefix = "[ ** ] "
    

    prefixes = [b_prefix, g_prefix, n_prefix]
    
    if args.passwd and not (args.genkey or args.encr or args.decr or args.key):
        
        _write_passwd_key(args.passwd, _gen_passwd_key(args.passwd), prefixes)

    elif args.genkey and not (args.passwd or args.encr or args.decr or args.key):

        _write_gen_key(_gen_key())
        
    elif args.passwd and args.encr and not (args.genkey or args.decr or args.key):

        _key = _gen_passwd_key(args.passwd)
        _write_passwd_key(args.passwd, _key, prefixes)
        _encr_and_write(args.encr, _key, prefixes)
        
    elif args.key and args.encr and not (args.passwd or args.decr or args.genkey):
        
        _encr_and_write(args.encr, args.key, prefixes)
            
    elif args.decr and args.key and not (args.encr or args.passwd or args.genkey):
        
        _decr_with_key(args.decr, args.key, prefixes)
            
    elif args.decr and args.passwd and not (args.encr or args.key or args.genkey):

        _decr_with_passwd(args.decr, args.passwd, prefixes)
        
    else:
        parser.print_help()

    sys.exit(0)

def _decr_with_key(data, key, prefixes):
    '''
    Decrypt file with pregenerated key

    @param data to be decrypted
    @param key file path
    @param array of color coded print prefixes
    '''
    try:
        
        if os.path.exists(key):
            with open(key, 'r') as in_key:
                _key = in_key.read()

            _fn = Fernet(_key)
        else:
            raise ValueError
        
        if os.path.exists(data):
            if ".encr" in data:
                
                with open(data, 'rb') as in_file:
                    _pt_data = in_file.read()
                    
                _decr_data = _fn.decrypt(_pt_data)
                _plain_file_name = data[:data.rfind(".")]

                with open(_plain_file_name, 'wb') as out_file:
                    out_file.write(_decr_data)

                os.remove(data)
                print(prefixes[1]+"Key provided: "+"\'"+key+"\'")
                print(prefixes[1]+"File processed: "+"\'"+data+"\'")
                print(prefixes[1]+"Decrypted file created: "+"\'"+_plain_file_name+"\'")
            else:
                TypeError
        else:
            print(prefixes[2]+"\'"+data+"\'"+" file not found, I'm assuming it's a string")
            _decr_data = _fn.decrypt(data.encode())
            print(prefixes[1]+"Key provided: "+"\'"+key+"\'")
            print(prefixes[1]+"Decrypted string: "+_decr_data.decode())
 
    except ValueError:
        print(prefixes[0]+"\'"+key+"\'"+" does not exist")
    except TypeError:
        print(prefixes[0]+"\'"+data+"\'"+" was not encrypted using this program")
    except InvalidToken:
        print(prefixes[0]+"Invalid Key")

def _decr_with_passwd(data, passwd, prefixes):
    '''
    Decrypt file with password

    @param data to be decrypted
    @param password
    @param array of color coded print prefixes
    '''
    _key = _gen_passwd_key(passwd)
    _fn = Fernet(_key)

    try:
        if os.path.exists(data):
            if ".encr" in data:
                
                with open(data, 'rb') as in_file:
                    _pt_data = in_file.read()
                    
                _decr_data = _fn.decrypt(_pt_data)
                _plain_file_name = data[:data.rfind(".")]

                with open(_plain_file_name, 'wb') as out_file:
                    out_file.write(_decr_data)

                os.remove(data)
                print(prefixes[1]+"Key provided: "+"\'"+passwd+"\'")
                print(prefixes[1]+"File processed: "+"\'"+data+"\'")
                print(prefixes[1]+"Decrypted file created: "+"\'"+_plain_file_name+"\'")
            else:
                TypeError
        else:
            print(prefixes[2]+"\'"+data+"\'"+" file not found, I'm assuming it's a string")
            _decr_data = _fn.decrypt(data.encode())
            print(prefixes[1]+"Key provided: "+"\'"+passwd+"\'")
            print(prefixes[1]+"Decrypted string: "+_decr_data.decode())
    except TypeError:
        print(prefixes[0]+"\'"+data+"\'"+" was not encrypted using this program")
    except InvalidToken:
        print(prefixes[0]+"Invalid password")

def _encr_and_write(in_file, key, prefixes):
    '''
    Encrypt file with pregenerated key and write to file system

    @param data to be encrypted
    @param key file path or password
    @param array of color coded print prefixes
    '''
    _fn = Fernet(key)

    if os.path.exists(in_file):
            
        with open(in_file, 'rb') as file_in:
            _pt_data = file_in.read()
                
        _encr_data = _fn.encrypt(_pt_data)
            
        with open(in_file+".encr",'wb') as out_file:
            out_file.write(_encr_data)
                
        os.remove(in_file)
            
    else:
        print(prefixes[0]+"\'"+in_file+"\'"+" file not found, I'm assuming it's a string")
        _pt_data = in_file
        _encr_data = _fn.encrypt(_pt_data.encode())
        print(prefixes[1]+"Encrypted string: "+_encr_data.decode())

def _write_passwd_key(passwd, pass_key, prefixes):
    '''
    Write out the key generated from password and show the password

    @param password
    @param key file path
    @param array of color coded print prefixes
    '''
    _key_file = ""
    with open('encr.key','wb') as new_key:
        new_key.write(pass_key)
        _key_file = os.path.abspath('encr.key')
    print(prefixes[1]+"Password provided: "+passwd)
    print(prefixes[1]+"New key: "+pass_key.decode())
    print(prefixes[1]+"Wrote new key to: "+_key_file)

def _write_gen_key(key, prefixes):
    '''
    Write out key

    @param key file path
    @param array of color coded print prefixes
    '''
    _key_file = ""
    with open('encr.key','wb') as new_key:
        new_key.write(key)
        _key_file = os.path.abspath('encr.key')
    print(prefixes[1]+"New key: "+key.decode())
    print(prefixes[1]+"Wrote new key to: "+_key_file)
    
def _gen_passwd_key(passwd):
    '''
    Generate key from password

    @param password
    @return hashed password
    '''
    _salt_str = "1337AF" # gen random salt
    _salt = str.encode(_salt_str)

    _passwd = passwd.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt = _salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(_passwd))
    
        
def _gen_key():
    '''
    Generate random key

    @return key
    '''
    return Fernet.generate_key()
    
if __name__ == "__main__":
    main()
