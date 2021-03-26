import socket
import sys
import threading
import base64
import time
from binascii import a2b_hex
from binascii import b2a_hex
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5



##登录模块
#-----------------------------------------------------------------------------------
#登录函数
def setlogin():

    #读取用户名信息
    def login(username, password):
        try:
            f = open("clientLoginDir.txt", 'r')  # 读文件
            for line in f:
                l1 = line.strip('\n')
                l1 = l1.split("|")
                if l1[0] == username and l1[1] == password:
                    return True
            return False
        except:
            print("无登录信息，请先注册！")

    #存储用户名信息
    def regedit(username, password):
        f = open("clientLoginDir.txt", 'a')  # a表示添加
        temp = username + "|" + password + "\n"
        f.write(temp)
        f.close()

    #判断用户名
    def start():
        a = input("1:登陆，2：注册：")
        if a == "1":
            username = input("请输入用户名：")
            password = input("请输入密码：")
            r = login(username, password)
            if r == True:
                print("登陆成功")
                flag = 1
                return flag
            else:
                print("登录失败")
        elif a == "2":
            print("注册")
            user = input("请输入用户名：")
            passwd = input("请输入密码：")
            regedit(user, passwd)
    f = start()
    return f



##RSA签名模块
#-----------------------------------------------------------------------------------
#获取RSA公私秘钥对
def getClientRSAKey():
    random_generator = Random.new().read  # rsa算法生成
    rsa = RSA.generate(1024, random_generator)  # 秘钥对的生成
    clientSKey = rsa.exportKey()  # server私钥
    clientPKey = rsa.publickey().exportKey()  # server公钥
    return clientSKey, clientPKey

#对明文签名
def Signature(serverSKey, message):
    rsakey = RSA.importKey(serverSKey)
    signer = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(message)
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    return signature

#对密文验签
def yzsignature(sign, serverPKey, msg):
    rsakey = RSA.importKey(serverPKey)
    verifier = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(msg)
    if verifier.verify(digest, base64.b64decode(sign)):
        return True
    else:
        return False




##RSA解密模块
#----------------------------------------------------------------------------
#RSA解密对称秘钥
def cSKeyDecrypt(clientSKey, key):
    rsakey = RSA.importKey(clientSKey)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    key = cipher.decrypt(base64.b64decode(key), Random.new().read)
    return key



##AES加解密模块
#----------------------------------------------------------------------------
#定义每16字节一块加密
def judge16(text):
 length = 16
 count = len(text)
 if count < length:
  add = (length - count)
  text = text + ('\0' * add).encode('utf-8')
 elif count > length:
  add = (length - (count % length))
  text = text + ('\0' * add).encode('utf-8')
 return text


#AES加密明文
def aesencrypt(msg, key):
    cryptor = AES.new(key, AES.MODE_CBC, b'0000000000000000')  # 用AES对秘钥处理
    mMsg = judge16(msg)
    s = cryptor.encrypt(mMsg)
    s = b2a_hex(s)
    #s = str(s, encoding='utf-8')
    return s

#AES解密密文
def decryptmMsg(mMsg, key):
    cryptor = AES.new(key, AES.MODE_CBC, b'0000000000000000')  # 解密内容
    mMsg = a2b_hex(mMsg)
    mMsg = cryptor.decrypt(mMsg)
    mMsg = bytes.decode(mMsg).rstrip('\0')
    return mMsg




##建立通信模块
#-----------------------------------------------------------------------------
#建立socket通信客户端
def client(clientPKey):

    #连接端口
    def connect(s, ip):
        try:
            s.connect((ip, 8888))
            print("connect success")
            print('connect time: ' + time.ctime())
        except ConnectionError:
            print('connect error')
            sys.exit(-1)
        except:
            print('unexpect error')
            sys.exit(-1)

    #发送函数
    def send_sth(s, key):
        while True:
            try:
                sth = input('输入消息内容：\n')
                sth = sth.encode('utf-8')  # 对消息二进制编码

                sign = Signature(clientSKey, sth)  # 对消息进行签名

                msg = aesencrypt(sth, key)  # AES加密消息

                szMsg = sign + b'$' + msg

                s.sendall(szMsg)  # 发送

            except ConnectionError:
                print('connect error')
                sys.exit(-1)
            except:
                print('unexpect error')
                sys.exit(-1)

    #接收函数
    def receive(s, serverPKey, key):
        while True:
            try:
                r = s.recv(2048)  # 接收2048位数据
                #print(type(r), r)

                r = r.split(b'$')
                msg = decryptmMsg(r[1], key)  # AES解密

                if yzsignature(r[0], serverPKey, msg.encode('utf-8')):  # 验签
                    print('收到新消息：' + msg + '\n输入消息内容：')
                else:
                    print("消息被篡改")

            except ConnectionError:
                print('connect error')
                sys.exit(-1)
            except:
                print('unexpect error')
                sys.exit(-1)

    #接收server公钥
    def recePKey(s):
        P = s.recv(1024)  # 接收的server公钥

        smkey = s.recv(1024)  # 接收加密后的对称秘钥

        smkey = smkey.split(b'$')
        mkey = cSKeyDecrypt(clientSKey, smkey[1])  # RSA解密对称秘钥
        if yzsignature(smkey[0], P, mkey):  # 签名判断是否更改
            return P, mkey
        else:
            print("对称秘钥被篡改")

    # 发送公钥
    def sendPkey(conn, clientPKey):
        try:
            conn.sendall(clientPKey)
        except:
            print('公钥分发失败')
            sys.exit(-1)


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = "127.0.0.1"
    connect(s, ip)

    sendPkey(s, clientPKey)
    serverPKey, key = recePKey(s)

    threading._start_new_thread(receive, (s, serverPKey, key))  # 启用另一线程用来收消息
    send_sth(s, key)  # 发送消息




if __name__ == '__main__':

    while True:
        flag = 0
        flag = setlogin()  # 登录
        if flag == 1:
            break

    a = '''
        ---------------欢迎使用-----------------
        '''
    print(a)

    clientSKey, clientPKey = getClientRSAKey()  # 获取client公私钥

    client(clientPKey)