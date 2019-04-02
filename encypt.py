'''
用于加密的模块。暂时只支持aes-256-cfb。
'''
# AES的总体加密流程如下：
# 1.把明文按照128bit拆分成若干个明文块。
# 2.按照选择的填充方式来填充最后一个明文块。
# 3.每一个明文块利用AES加密器和密钥，加密成密文块。
# 4.拼接所有的密文块，成为最终的密文结果。

# 依赖于PyCryptodome库

import base64
import hashlib
import os

from Crypto.Cipher import AES

# 目前仅支持aes-256-cfb
# 在aes-256-cfb中，我们选择32位密钥长度，16位初始向量
KEYLEN = 32
IVLEN = 16

ENCRYPT = 1
DECRYPT = 0

# 密钥缓存
cached_keys = {}


class aes_256_cfb_Cyptor:
    '''
    AES-256-cfb加密类。
    '''
    KEYLEN = 32
    IVLEN = 16
    ENCRYPT = 1
    DECRYPT = 0

    def __init__(self, passwd):
        self.ciptor = None
        self.deciptor = None
        self.passwd = passwd
        self.iv = None

    def cipher(self, data):
        if not self.ciptor:
            iv = os.urandom(self.IVLEN)
            key, _ = EVP_BytesToKey(self.passwd, self.KEYLEN, self.IVLEN)

            ciptor = AES.new(key, AES.MODE_CFB, iv)
            encrypted = ciptor.encrypt(data)

            self.key = key
            self.iv = iv
            self.ciptor = ciptor

            return iv + encrypted
        else:
            return self.ciptor.encrypt(data)

    def decipher(self, data):
        if not self.deciptor:
            iv = data[:IVLEN]
            data = data[IVLEN:]
            deciptor = AES.new(self.key, AES.MODE_CFB, iv)
            text = deciptor.decrypt(data)
            self.deciptor = deciptor
        else:
            text = deciptor.decrypt(data)
        return text


def EVP_BytesToKey(password, key_len, iv_len):
    '''
    使用OpenSSL中的同名函数，通过不定长的密码生成定长的密钥和初始向量。
    '''
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv
