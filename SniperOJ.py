# -*- coding: utf-8 -*-

import requests
import rsa
import json
import pathlib

host = "127.0.0.1"
port = 5000
pem_folder = '.pem'
private_pem_filename = 'private.pem'
public_pem_filename = 'public.pem'
private_pem_path = "%s/%s" % (pem_folder, private_pem_filename)
public_pem_path = "%s/%s" % (pem_folder, public_pem_filename)
key_size = 512


session = requests.Session()


def check_rsa_key_pair_existed():
    private_existed = pathlib.Path(private_pem_path).is_file()
    public_existed = pathlib.Path(public_pem_path).is_file()
    return private_existed or public_existed


def generate_rsa_key_pair(overwrite=False):
    (public_pem, private_pem) = rsa.newkeys(key_size)
    # both key are not existed, then write directly
    if (not check_rsa_key_pair_existed()) or overwrite:
        with open(private_pem_path, "wb+") as f:
            f.write(private_pem.save_pkcs1())
        with open(public_pem_path, "wb+") as f:
            f.write(public_pem.save_pkcs1())
        return (private_pem_path, public_pem_path)
    return False


def register():
    route = "register"
    url = "http://%s:%d/%s" % (host, port, route)
    key_pair = generate_rsa_key_pair()
    if not key_pair:
        print("[-] RSA keys already exitsed.")
        answer = raw_input("[?] Overwrite? [Y/N]").strip(" \t\n").lower()
        if answer.startswith('n'):
            return False
        else:
            key_pair = generate_rsa_key_pair(overwrite=True)
    email = raw_input("Input email: ").strip(" \t\n")
    data = {
        "email": email,
        "public_pem": open(key_pair[1]).read()
    }
    response = session.post(url, data=data)
    print(response.content)
    result = json.loads(response.text)
    if result['status']:
        print("[+] %s" % (result['msg']))
    else:
        print("[-] %s" % (result['msg']))


def auth(email):
    route = "auth"
    url = "http://%s:%d/%s" % (host, port, route)
    data = {
        "email": email
    }
    response = session.post(url, data=data)
    result = json.loads(response.text)
    if result['status']:
        challenge = result['msg']
        print("[+] Challenge string: %s" % (challenge))
        # Private key
        with open(private_pem_path) as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read().encode())
        answer = rsa.decrypt(challenge.decode("base64"), private_key)
        print("[+] Decrypted answer: %s" % (answer))
        return answer
    else:
        msg = result['msg']
        print("[-] %s" % (msg))
        return False


def submit():
    # Check rsa key
    if not check_rsa_key_pair_existed():
        print("[-] RSA key pair lost!")
        print("[-] Maybe you should register first or reset the rsa key!")
        return False
    # Auth
    email = raw_input("Input email: ").strip(" \t\n")
    answer = auth(email)
    if not answer:
        return False
    # Submit flag
    route = "submit"
    url = "http://%s:%d/%s" % (host, port, route)
    flag = raw_input("Input flag: ").strip(" \t\n")
    data = {
        "auth": answer,
        "flag": flag
    }
    response = session.post(url, data=data)
    result = json.loads(response.text)
    if result['status']:
        print("[+] %s" % (result['msg']))
        print("[+] Your profile and global rank will be update soon!")
    else:
        print("[-] %s" % (result['msg']))


def main():
    # register()
    submit()


if __name__ == '__main__':
    main()