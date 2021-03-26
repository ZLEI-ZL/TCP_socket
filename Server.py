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

    #读取用户名密码
    def login(username, password):
        try:
            f = open("serverLoginDir.txt", 'r')  # 读文件
            for line in f:
                l1 = line.strip('\n')
                l1 = l1.split("|")
                if l1[0] == username and l1[1] == password:
                    return True
            return False
        except:
            print("无登录信息，请先注册！")

    #保存用户名密码
    def regedit(username, password):
        f = open("serverLoginDir.txt", 'a')  # a表示添加
        temp = username + "|" + password + '\n'
        f.write(temp)
        f.close()

    #用户名密码判断
    def start():
        a = input("1:登陆，2：注册，3：修改加密秘钥：")
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
        elif a == "3":
            print("修改对称密码")
            key = input("输入传输加密秘钥（16位数字）：")
            key = key.encode()
            saveAESKey(key)

    f = start()
    return f



##RSA签名模块
#-----------------------------------------------------------------------------------
#获取RSA公私秘钥对
def getServerRSAKey():
    random_generator = Random.new().read  # rsa算法生成
    rsa = RSA.generate(1024, random_generator)  # 秘钥对的生成
    serverSKey = rsa.exportKey()  # server私钥
    serverPKey = rsa.publickey().exportKey()  # server公钥

    return serverSKey, serverPKey

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
def yzsignature(sign, clientPKey, msg):  # 验签
    rsakey = RSA.importKey(clientPKey)
    verifier = Signature_pkcs1_v1_5.new(rsakey)
    digest = SHA.new()
    digest.update(msg)
    if verifier.verify(digest, base64.b64decode(sign)):
        return True
    else:
        return False



##RSA加密模块
#-----------------------------------------------------------------------------------
#公钥加密AES密码
def RSAEncrypt(clientPKey, key):
    rsakey = RSA.importKey(clientPKey)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(key))
    return cipher_text



##AES加解密模块
#-----------------------------------------------------------------------------------
#保存秘钥
def saveAESKey(key):
    with open("AESKey.txt", "wb") as fo:
        fo.write(key)

#获取对称秘钥
def getAESKey():
    try:
        with open("AESKey.txt", "rb") as fo:
            key = fo.readline()

        return key
    except:
        key = input("请先输入加密秘钥（16位数字）：")
        key = key.encode('utf-8')
        saveAESKey(key)
        return key

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
    mMsg = judge16(msg)  # 将消息16位分割
    s = cryptor.encrypt(mMsg)
    s = b2a_hex(s)
    return s

#AES解密密文
def decryptmMsg(mMsg, key):
    cryptor = AES.new(key, AES.MODE_CBC, b'0000000000000000')  # 解密内容
    mMsg = a2b_hex(mMsg)
    mMsg = cryptor.decrypt(mMsg)
    mMsg = bytes.decode(mMsg).rstrip('\0')
    return mMsg




##发送端模块
#--------------------------------------------------------------------------------
#建立socket通信服务端
def server(serverPKey, key):

    #绑定地址和端口
    def bind():
        HOST = '127.0.0.1'
        s.bind((HOST, 8989))
        #print("bind ok")

    #监听
    def listen():
        s.listen(10)
        print('waitting connect')

    #发送消息函数
    def send_sth(conn):
        while True:
            try:
                sth = input('输入消息内容：\n')
                sth = sth.encode('utf-8')  # 将消息二进制编码

                sign = Signature(serverSKey, sth)  # 对消息进行签名

                msg = aesencrypt(sth, key)  # AES加密消息

                szMsg = sign + b'$' + msg
                #print(type(szMsg), szMsg)

                conn.sendall(szMsg)  # 发送

            except ConnectionError:
                print('connect error')
                sys.exit(-1)
            except:
                print('unexpect error')
                sys.exit(-1)

    #接收消息
    def recv(conn, clientPKey):
        while True:
            try:
                data = conn.recv(2048)  # 接收

                data = data.split(b'$')  # 以$符号分割消息
                msg = decryptmMsg(data[1], key)  # AES解密

                if yzsignature(data[0], clientPKey, msg.encode('utf-8')):  # 验签
                    print('收到新消息：' + msg + '\n输入消息内容：')
                else:
                    print("消息被篡改")

            except ConnectionError:
                print('connect error')
                sys.exit(-1)
            except:
                print('unexpect error')
                sys.exit(-1)

    #发送秘钥
    def sendkey(conn, serverPKey, key, clientPKey):
        try:
            conn.sendall(serverPKey)  # 发送server公钥

            signKey = Signature(serverSKey, key)  # 对秘钥签名
            mKey = RSAEncrypt(clientPKey, key)  # rsa加密秘钥
            smKey = signKey + b'$' + mKey
            conn.sendall(smKey)  # 发送对称秘钥
        except:
            print('公钥分发失败')
            sys.exit(-1)

    #接收client公钥
    def recePKey(conn):
        P = conn.recv(1024)
        return P


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind()
    listen()
    conn, addr = s.accept()
    print("connect success")
    print('connect time: ' + time.ctime())

    clientPKey = recePKey(conn)  # 接收client公钥
    sendkey(conn, serverPKey, key, clientPKey)  # 发送server公钥和对称秘钥

    threading._start_new_thread(recv, (conn, clientPKey))  # 打开另一线程用于实时接收
    send_sth(conn)  # 发送消息内容



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

    serverSKey, serverPKey = getServerRSAKey()

    key = getAESKey()

    server(serverPKey, key)