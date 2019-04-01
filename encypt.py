'''
用于加密的模块。暂时只支持aes-256-cfb。
'''
# AES的总体加密流程如下：
# 1.把明文按照128bit拆分成若干个明文块。
# 2.按照选择的填充方式来填充最后一个明文块。
# 3.每一个明文块利用AES加密器和密钥，加密成密文块。
# 4.拼接所有的密文块，成为最终的密文结果。

# 依赖于M2Crypto库

import hashlib
import base64
import M2Crypto.EVP
import os

# 目前仅支持aes-256-cfb
# 在aes-256-cfb中，我们选择32位密钥长度，16位初始向量
KEYLEN = 32
IVLEN = 16

ENCRYPT = 1
DECRYPT = 0

# 密钥缓存
cached_keys = {}


class aes_256_cfb_Cyptor:

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

            cipher = M2Crypto.EVP.Cipher('aes_256_cfb', key, iv, self.ENCRYPT)
            encrypted = cipher.update(data) + cipher.final()

            self.key = key
            self.iv = iv
            self.ciptor = cipher  

            return iv + encrypted
        else:
            return self.ciptor.update(data) + self.ciptor.final()

    def decipher(self, data):
        if not self.deciptor:
            deciptor = M2Crypto.EVP.Cipher('aes_256_cfb', self.key, self.iv, self.DECRYPT)
        text = deciptor.update(data) + deciptor.final()
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


def encrypt(passwd, text):
    '''
    生成定长的随机初始化向量。使用密码生成密钥。将初始化向量置于密文后返回。
    '''
    iv = os.urandom(IVLEN)
    key, _ = EVP_BytesToKey(passwd, KEYLEN, IVLEN)
    cipher = M2Crypto.EVP.Cipher('aes_256_cfb', key, iv, ENCRYPT)
    encrypted = cipher.update(text) + cipher.final()
    return iv + encrypted


def decrypt(passwd, encrypted):
    '''
    从密文中提取初始化向量，利用密钥解密后得到明文。
    '''
    iv = encrypted[:IVLEN]
    data = encrypted[IVLEN:]
    key, _ = EVP_BytesToKey(passwd, KEYLEN, IVLEN)
    cipher = M2Crypto.EVP.Cipher('aes_256_cfb', key, iv, DECRYPT)
    text = cipher.update(data) + cipher.final()
    return text


def der(text):
    print()
    print(decrypt(PASSWORD, text))


# 测试
if __name__ == '__main__':
    PASSWORD = b"Glgj3417inhfBQZ"

    data = b"GET / HTTP/1.1"
    en = encrypt(PASSWORD, data)
    de = decrypt(PASSWORD, en)
    assert data == de

    b = b"\x45\xda\xcb\x49\xb6\xc9\x70\xf8\xa2\x27\x31\xfc\x49\x12" \
        b"\x8c\xfb\x0e\x23\x73\x09\x80\x1e\xe9\x05\x8a\x18\x44\x40\x90\x87" \
        b"\xce\x39\xa1\x46\x5e\x75\xd3\x2c\xe3\x69\x5d\xc8\x03\xfd\xcc\xd1" \
        b"\xa3\xe6\x40\xf2\x0c\x3b\x19\xcb\xeb\xcd\xf9\xe2\x56\x3e\x26\x04" \
        b"\xcf\x6c\xd5\xb1\x99\xf2\xe6\xd0\xed\xa3\x53\xa1\x68\x0c\xf2\xe3" \
        b"\xfc\x45\x6c\x9c\xfb\x35\xc6\xa9\x52\xdb\xe8\xe1\x49\x06\x05\xa2" \
        b"\x0c\x29\x6d\xb2\xb5\x43\xf7\x6a\xcc\x3f\x12\x24\x4a\x88\xf5\xf4" \
        b"\x8b\x6a\xf4\x36\xa5\xbf\x96\xc2\x69\xce\x22\xbe\xcf\x6e\x8c\xe6" \
        b"\xfa\xec\x9f\xd5\x40\xc8\xb1\x0d\x07\xf7\xa4\xa6\x59\x85\x9b\xd7" \
        b"\x39\xef\xba\xba\xe9\x32\x63\xfb\x8d\xc0\xbe\x7c\x7f\x01\x0a\x11" \
        b"\x79\xf6\x3f\x41\x1c\xc7\x95\x73\x17\x05\x6e"

    der(b)

    b = b"\x4a\xb4\x07\x63\xcd\xe8\xd5\x1c\x05\x8a\xb0\xfe\xe2\x1a" \
        b"\x59\x20\xbf\x46\xae\xd1\x2d\xf2\x0a\x2e\xac\xb0\xb5\xee\x71\x0e" \
        b"\x1b\x2b\xca\x15\x63\xc1\x3e\x78\xeb\xdf\xa2\x94\x1c\x91\xcc\xcc" \
        b"\xad\x4d\x38\xb0\x82\xf2\x90"

    der(b)

    b = b"\x3a\xc6\xb1\x0e\x61\x84\x1d\x9f\xdd\xff\x91\xf5\x3d\x5c" \
        b"\x59\x04\x04\xe2\x0b\xef\xbf\xf0\xa4\x01\xcf\xbc\x65\xe4\xc2\x93" \
        b"\x90\x86\x7c\xff\x68\x2d\x65\x4e\x38\x3d\x47\x5a\x73\x95\x4f\x7f" \
        b"\x12\x9a\x90\x33\xa1\x24\xd6\x23\x46\xc4\x2f\xc9\x4c\x76\xe3\xd3" \
        b"\xb1\xe2\xf8\x0e\x96\x9a\x85\x44\x81\xb9\xf3\x8a\x3b\x92\xae\x1a" \
        b"\x23\xe4\x3b\x0f\x03\xa3\x3c\xe4\x90\xd3\x7f\x46\x09\xd3\x4f\x59" \
        b"\x1c\x96\xc7\x81\xe0\xc4\xb4\x21\x0a\xc0\xa1\xde\xee\xd7\x39\xf8" \
        b"\x44\x2a\x81\x26\xf2\xcf\xe9\x8c\x39\x4e\xaa\xcb\xb1\x07\xe5\xa9" \
        b"\x3a\x82\x5f\x54\x60\x06\x58\xb3\x43\xae\x95\xdb\xcc\x64\x26\xff" \
        b"\x34\x71\x72\x2a\x39\x7d\x23\xa5\x14\x1b\xce\x6d\x0d\x70\xa8\xaf" \
        b"\x93\x9d\xe6\xfa\xe6\x09\x15\xb3\xba\x5e"

    der(b)

    b = b"\x72\xa1\x69\x2d\xf4\xd1\xe0\x00\x9e\xcd\xe2\x89\x08\x84" \
        b"\xbf\xfd\xff\x14\xdb\xba\xc7\x45\x6c\x06\x20\xeb\x69\x14\xf6\x10" \
        b"\x3c\x89\x59\xac\xa2\x93\x0d\xfe\x95\x56\x76\xcb\xb2\x6a\x15\x5c" \
        b"\xa7\xbc\xac\x5d\x63\x43\x08\xa1\x59\x7d\x87\xc1\x06\x7a\xc5\x74" \
        b"\xdf\xe8\xe7\xb3\x0d\x79\x33\x6f\xad\x6b\xfa\xfb\x35\x49\xfb\xb5" \
        b"\x18\x1d\x64\x65\x1e\xdd\x59\x5d\x90\xb2\xe0\x53\x04\x93\xa2\xf0" \
        b"\x56\x28\xb9\x1d\x00\xfd\x64\x85\xa0\x2e\xfd\xff\x45\x32\xde\x6b" \
        b"\xa7\xd4\x1a\x39\x34\x0a\xf4\xda\x3f\x03\x25\x13\xb3\x0a\xa4\x57" \
        b"\x3e\x7b\x7e\xca\x9e\xe2\x79\x6c\x8e\x93\xec\x65\x9b\x67\x7a\x27" \
        b"\xed\x72\x64\x7a\x51\xe4\xab\xe3\x8e\x81\x4e\xef\xce\x8b\xd2\x80" \
        b"\x23\x03\x60\x42\x33\xcc\xdf\x8b\xf6\x5e\xc1\xdb"

    der(b)

