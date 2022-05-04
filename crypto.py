from Crypto import Cipher
from Crypto import Signature
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256 
import os
import sys




def write_file_contents(filename,msg):
    file_out=open(os.path.join(sys.path[0],filename),'wb')
    file_out.write(msg)
    file_out.close()




def DES3_encryption(key) :
    try:
        filename=input("\nPlease specify the file to encrypt.\n")
        plaintext = open(os.path.join(sys.path[0],filename),'rb').read()
    except:
        print("\nERROR : Choose a valid file.")
        
    cipher = DES3.new(key,DES3.MODE_CBC)
    encrypted_msg = cipher.iv + cipher.encrypt(pad(plaintext,DES3.block_size))
    write_file_contents("3des_encrypted_file.txt",encrypted_msg)
    print("\nSuccess : Encrypted message is saved in => 3des_encrypted_file.txt")
    

def DES3_decryption(key):
    try:
        filename=input("\nPleace specify the file to decrypt.\n")
        file=open(os.path.join(sys.path[0],filename),'rb')
        iv=file.read(8)
        cipher=DES3.new(key,DES3.MODE_CBC,iv)
        encrypted_msg=file.read()
        decrypted_msg=unpad(cipher.decrypt(encrypted_msg),DES3.block_size)
        write_file_contents("3des_decrypted_file.txt",decrypted_msg)
        print("\nSuccess : Decrypted message is saved in => 3des_decrypted_file.txt")
    except:
        print("\nERROR : Choose a valid file.")
    
def DES_encryption(key):
    try:
        filename=input("\nPleace specify the file to encrypt.\n")
        plaintext = open(os.path.join(sys.path[0],filename),'rb').read()
    except:
         print("\nERROR : Choose a valid file.")
    
    cipher=DES.new(key,DES.MODE_CBC)
    encrypted_msg= cipher.iv + cipher.encrypt(pad(plaintext,DES.block_size))
    write_file_contents("des_encrypted_file.txt",encrypted_msg)
    print("\nSuccess : Encrypted message is saved in => des_encrypted_file.txt")

def DES_decryption(key):
    try:
        filename=input("\nPleace specify the file to decrypt.\n")
        file=open(os.path.join(sys.path[0],filename),'rb')
        iv= file.read(8)
        encrypted_msg=file.read()
        cipher=DES.new(key,DES.MODE_CBC,iv)
        decrypted_msg= unpad(cipher.decrypt(encrypted_msg),DES.block_size)
        write_file_contents("des_decrypted_file.txt",decrypted_msg)
        print("\nSuccess : Decrypted message is saved in => des_decrypted_file.txt")
    except:
        print("\nERROR : Choose a valid file.")
    


def AES_encryption(key):
    try:
        filename=input("\nPlease specify the file to encrypt.\n")
        plaintext=open(os.path.join(sys.path[0],filename),'rb').read()
    except:
        print("\nERROR : Choose a valid file.")
    cipher=AES.new(key,AES.MODE_CBC)
    encrypted_msg=cipher.iv + cipher.encrypt(pad(plaintext,AES.block_size))
    write_file_contents("aes_encrypted_file.txt",encrypted_msg)
    print("\nSuccess : Encrypted message is saved in => aes_encrypted_file.txt")

def AES_decryption(key):
    try:
        filename=input("Please specify the file to decrypt.\n")
        file=open(os.path.join(sys.path[0],filename),'rb')
        iv=file.read(16)
        cipher=AES.new(key,AES.MODE_CBC,iv)
        encrypted_msg=file.read()
        decrypted_msg=unpad(cipher.decrypt(encrypted_msg),AES.block_size)
        write_file_contents("aes_decrypted_file.txt",decrypted_msg)
        print("\nSuccess : Decrypted message is saved in => aes_decrypted_file.txt")
    except:
        print("\nERROR : Choose a valid file.")
   

def generate_private_public_key_pair():
    try:    
        print("Generating ...")
        key = RSA .generate(2048)
        private_key=key.export_key()
        file_out=open(os.path.join(sys.path[0],"private_key.pem"),'wb')
        file_out.write(private_key)
        file_out.close()
        public_key=key.public_key().export_key()
        file_out=open(os.path.join(sys.path[0],"public_key.pem"),"wb")
        file_out.write(public_key)
        file_out.close()
    except:
        print("\ERROR : generating priv/pub key pair.")

    print("\nDone Generating priv/pub key pair:")
    print("\nPrivate Key => private_key.pem")
    print("Public Key => public_key.pem")
    

def sign_file():
    try:
        private_key=input("\nPlease specify the path of the private key.\n")
        filename=input("\nPlease specify the path of the file to sign.\n")
        key=RSA.import_key(open(os.path.join(sys.path[0],private_key)).read())
        hash = SHA256.new(open(os.path.join(sys.path[0],filename),"rb").read())
    except(ValueError,TypeError):
        print("\nERROR : Choose a valid private key.")
    except:
        print("\nERROR : Choose a valid file.")
    signature=pkcs1_15.new(key).sign(hash)
    file_out=open(os.path.join(sys.path[0],"signature_"+filename),"wb")
    file_out.write(signature)
    file_out.close()
    print(f'Success : the signature of the file \"{filename}\" has been saved in => signature_{filename} ')

   

def verify_signature():
    public_key=input("\nPlease specify the path of public key.\n")
    key=RSA.import_key(open(os.path.join(sys.path[0],public_key)).read())
    try:  
        filename=input("\nPlease specify the path of the file.\n")
    except:
       print("\nERROR : Choose a valid file.")

 
    try:
        signature=input("\nPlease specify the path of the signature file.\n")
        signature= open(os.path.join(sys.path[0],signature),"rb").read()
        hash=SHA256.new(open(os.path.join(sys.path[0],filename),"rb").read())
        pkcs1_15.new(key).verify(hash,signature)
        print("\nThe signature is valid.")
    except (ValueError,TypeError):
        print("\nThe signature is not valid.")



def menu(triple_des_key,des_key,aes_key):
        
     
    print("\n"
    "    /`      |-          |_           . _  _|-\n"
    "    \,|`\/|)|_()(||`(||)||\/  |)|`() |(/_(_|_\n"
    "        / |     _|    |   /   |     _|\n"       
    "")


    print("\n[1]: Generate private,public key pair")
    print("[2]: Encrypt data")
    print("[3]: Decrypt data")
    print("[4]: Sign a file")
    print("[5]: Verify a file's signature")
    print("[0]: Quit")
    choice=int(input())
    while choice!=0 :
        if choice==1:
            generate_private_public_key_pair()
        elif choice==2:
            print("\n[1] Encrypt using 3DES")
            print("[2] Encrypt using DES")
            print("[3] Encrypt using AES")
            print("[0] Back")
            choice=int(input())
            while choice!=0 :
                if choice==1:
                    DES3_encryption(triple_des_key)
                elif choice==2:
                    DES_encryption(des_key)
                elif choice==3:
                    AES_encryption(aes_key)
                print("\n[1] Encrypt using 3DES")
                print("[2] Encrypt using DES")
                print("[3] Encrypt using AES")
                print("[0] Back")
                choice=int(input())
        elif choice==3:
            print("\n[1] Decrypt a 3DES encrypted file")
            print("[2] Decrypt a DES encrypted file")
            print("[3] Decrypt a AES encrypted file")
            print("[0] Back")
            choice=int(input())
            while choice!=0 :
                if choice==1:
                    DES3_decryption(triple_des_key)
                elif choice==2:
                    DES_decryption(des_key)
                elif choice==3:
                    AES_decryption(aes_key)
                print("\n[1] Decrypt a 3DES encrypted file")
                print("[2] Decrypt a DES encrypted file")
                print("[3] Decrypt a AES encrypted file")
                print("[0] Back")
                choice=int(input())     
        elif choice==4:
            sign_file()
        elif choice==5:
            verify_signature()
        
        print("\n[1]: Generate private,public key pair")
        print("[2]: Encrypt data")
        print("[3]: Decrypt data")
        print("[4]: Sign a file")
        print("[5]: Verify a file's signature")
        print("[0]: Quit")
        choice=int(input())




if __name__ == "__main__":
    triple_des_key = DES3.adjust_key_parity(get_random_bytes(24))
    des_key = get_random_bytes(8)
    aes_key=get_random_bytes(16)
    menu(triple_des_key,des_key,aes_key)
    






