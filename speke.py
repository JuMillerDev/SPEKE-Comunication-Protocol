import base64
import sys
from sys import argv
import hashlib
import random
from Crypto.Cipher import AES
from Crypto import Random

p = "0xCE369E8F9F2B0F43C0E837CCEC78439B97FF11D2E8DD3DDC57836F8DE11DF848D1CF99615C23BAA3BCF87D9D5DDDE981CFA885647780FEFA21CB07265561AF679BA170E9547E125ECC7B340DCAC3D9F6BF38AF243B01125D1CB0ADCDD80024A235CF25B8ABD5DAEC18AE0E063673DAE2DBFB416AF60E1233320490E1218DA5AD16C91527076E36A7DA9623715428F80010BB9F30477BFCC89F3183D343184A18E938CAB6EF364BE069FA7BE251AA267C6BFE62F247AC1A72BE7830EDB769E195E3CD6BB13DD684FE10DD9C042A465ADF46E0C5EF6458D0304DEE3437B940C904B235DB669A4013198A8184AE7F060F903EAFAB3150E24C011CBE57FAD7BAA1B62DEFB53B2DF0F51019DC339D2D25AA00F904E1AA17E1005B"
password = "asdf"

def X(password,randValue):
    hashobj = int((hashlib.sha256(password.encode('utf-8')).hexdigest()),16)
    val = pow(hashobj,randValue,int(p,16))
    res = base64.b64encode(val.to_bytes(((val.bit_length()+7)//8), byteorder="big"))
    return(res.decode("ascii"))

def K(x,randValue):
    x2 = (int.from_bytes((base64.b64decode(x)), "big"))
    val = pow(x2,randValue,int(p,16))
    hash = (hashlib.sha256(val.to_bytes((val.bit_length()+7)//8, byteorder="big")))
    hashed = (hash.digest())
    return(hashed)

def eEncode(k,c):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return(base64.b64encode(iv + cipher.encrypt((c)))).decode("ascii")

def eDecode(k, e):
    enc = base64.b64decode(e)
    iv = enc[:AES.block_size]
    cipher = AES.new(k, AES.MODE_CBC, iv)
    decryption = cipher.decrypt(enc[AES.block_size:])
    return(decryption)

def B():
    val = input("Password > ")
    if(val != password or not len(val) == len(val.encode())):
        print("FAIL: wrong text format")
        sys.exit()
    Xa = input("XA > ")
    if((len(Xa)*3)/4-Xa.count('=', -2) != 280):
        print("FAIL: wrong amount of bytes")
        sys.exit()
    b = random.getrandbits(4000)
    Xb = X(password,b)
    print("XB >", Xb)
    e1 = input("E1 > ")
    k = K(Xa, b)
    Ca = eDecode(k, e1)
    Cb = Random.get_random_bytes(16)
    enc = b''.join([Cb,Ca])
    print("E2 >", eEncode(k,enc))
    e3 = input("E3 > ")
    if (eDecode(k,e3) == Cb):
        print("PASS")
        print("KEY >", base64.b64encode(k).decode("ascii"))
        sys.exit()
    else:
        print("FAIL")
        sys.exit()

def A():
    val = input("Password > ")
    if(val != password or not len(val) == len(val.encode())):
        print("FAIL: wrong text format")
        sys.exit()
    a = random.getrandbits(4000)
    Xa = X(password,a)
    print("XA >", Xa)
    Xb = input("XB > ")
    if((len(Xb)*3)/4-Xb.count('=', -2) != 280):
        print("FAIL: wrong amount of bytes")
        sys.exit()
    k = K(Xb, a)
    Ca = Random.get_random_bytes(16)
    e1 = eEncode(k,Ca)
    print("E1 >",e1)
    e2 = input("E2 > ")
    dec = eDecode(k,e2)
    if(dec[16:] == Ca):
        print("E3 >", eEncode(k, dec[:-16]))
        print("PASS")
        print("KEY >", base64.b64encode(k).decode("ascii"))
        sys.exit()
    else:
        print("FAIL")

if __name__ == "__main__":
    if (argv[1] == "A"):
        A()
    elif(argv[1] == "B"):
        B()