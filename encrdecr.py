#!/usr/bin/env python3

import base64, os, argparse, sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g','--genkey',action='store_true',dest='genkey',help='Generate new random key')
    parser.add_argument('-p','--passwd',action='store',dest='passwd',help='Generate key from password')
    parser.add_argument('-e','--encrypt',action='store',dest='encr',help='Encrypt this file or string')
    parser.add_argument('-d','--decrypt',action='store',dest='decr',help='Decrypt this file or string')
    parser.add_argument('-k','--key',action='store',dest='key',help='Use this key')
    
    args = parser.parse_args()

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

    prefixes = [b_prefix, g_prefix,n_prefix]
    
    if args.genkey and not (args.encr or args.decr or args.key or args.passwd):
        
        _write_gen_key(_gen_key(), prefixes)
        
    elif args.passwd and not (args.genkey or args.encr or args.decr):
        
        _write_passwd_key(_gen_passwd_key(args.passwd))

    elif args.genkey and args.encr and not (args.decr or args.passwd):
        print("hey")
        _key = _gen_key()
        _write_gen_key(_key, prefixes)
        try:
            if os.path.exists(args.encr):
                
                #_fp = os.path.abspath(args.encr)
                with open(args.encr, 'rb') as in_file:
                    _pt_data = in_file.read()
                _encr_and_write(args.encr, _pt_data, _key, prefixes)
            else:
                raise FileNotFoundError
        except FileNotFoundError:
            print(prefixes[0]+"\'"+args.encr+"\'"+" file not found, I'm assuming it's a string")
            _pt_data = args.encr
            _encr_str(_pt_data.encode(), _key, prefixes)
            
    sys.exit(0)

def _encr_str(data, key, prefixes):
    _fn = Fernet(key)
    _encr_data = _fn.encrypt(data)
    print(prefixes[1]+"Encrypted string: "+_encr_data.decode())

def _encr_and_write(in_file, data, key, prefixes):
    _fn = Fernet(key)
    _encr_data = _fn.encrypt(data)
    with open(in_file+".encr",'wb') as out_file:
        out_file.write(_encr_data)

def _write_passwd_key(pass_key, prefixes):
    _key_file = ""
    with open('encr.key','wb') as new_key:
        new_key.write(_key)
        _key_file = os.path.abspath('encr.key')
    print(prefixes[1]+"Password provided: "+args.passwd)
    print(prefixes[1]+"New key: "+_key.decode())
    print(prefixes[1]+"Wrote new key to: "+_key_file)

def _write_gen_key(key, prefixes):
    _key_file = ""
    with open('encr.key','wb') as new_key:
        new_key.write(key)
        _key_file = os.path.abspath('encr.key')
    print(prefixes[1]+"New key: "+key.decode())
    print(prefixes[1]+"Wrote new key to: "+_key_file)
    
def _gen_passwd_key(passwd):
    _salt = b'\xf2.\xd6\x83\x93\xa9B\xf4\x9e2\xae\x1a\xb0y\xccS'
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

    return Fernet.generate_key()
    
if __name__ == "__main__":
    main()
