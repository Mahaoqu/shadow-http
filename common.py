import asyncio
import logging
import struct
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton, IPPROTO_TCP

from encypt import aes_256_cfb_Cyptor


def compat_ord(s):
    if type(s) == int:
        return s
    return ord(s)


def compat_chr(d):
    if bytes == str:
        return chr(d)
    return bytes([d])


def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s


def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s


def is_ip(address):
    for family in (AF_INET, AF_INET6):
        try:
            if type(address) != str:
                address = address.decode('utf8')
            inet_pton(family, address)
            return family
        except (TypeError, ValueError, OSError, IOError):
            pass
    return False


class BadHttpHeader(Exception):
    pass


class NoAcceptableMethods(Exception):
    pass


class BadShadowHeader(Exception):
    pass


def parse_http(buffer):
    http_head = buffer.split(b'\n')[0].split(b' ')
    if http_head[0] != b'CONNECT':
        raise NoAcceptableMethods
    try:
        x = http_head[1].split(b':')
        return (x[0], int(x[1]))
    except:
        raise BadHttpHeader


def make_shadow_head(addr):
    '''
    通过主机名和端口号封装Shadows头
    '''
    head = b''
    host = addr[0]
    port = addr[1]
    family = is_ip(host)

    # hostname
    if family == False:
        head += b'\x03'
        head += len(host).to_bytes(1, 'big')
        head += to_bytes(host)

    elif family == AF_INET:
        head += b'\x01'
        head += to_bytes(inet_pton(family, host))

    else:
        head += b'\x04'
        head += to_bytes(inet_pton(family, host))

    head += port.to_bytes(2, 'big')
    return head


async def parse_shadow_head(head):
    '''
    解析Shadow头，并返回主机名，端口号和头部长度
    '''
    atype = head[0]
    length = 1

    # IPv4
    if atype == 0x01:
        host = inet_ntop(AF_INET, head[length:length + 4])
        length += 4

    # IPv6
    elif atype == 0x04:
        host = inet_ntop(AF_INET, head[length:length + 16])
        length += 16

    # 域名
    elif atype == 0x03:
        addr_len = head[length]
        length += 1
        hostname = head[length:length + addr_len]
        logging.debug(f'解析域名{hostname}...')
        length = length + addr_len
        host = await asyncio.get_event_loop().getaddrinfo(hostname, None, proto=IPPROTO_TCP,
                                                          family=AF_INET)
        host = host[0][4][0]
        logging.debug(f'解析成功，{hostname}的地址是{host}')

    else:
        raise BadShadowHeader

    port = struct.unpack('!H', head[length:length + 2])[0]
    length += 2

    logging.debug(f'请求访问{host}:{port}')
    return host, port, length


# def parse_shadow_head(head):
#     '''
#     解析Shadow头，并返回主机名，端口号和头部长度
#     '''
#     atype = head[0]
#     length = 1

#     # IPv4
#     if atype == 0x01:
#         host = inet_ntop(AF_INET, head[length:length + 4])
#         length += 4

#     # IPv6
#     elif atype == 0x04:
#         host = inet_ntop(AF_INET, head[length:length + 16])
#         length += 16

#     # 域名
#     elif atype == 0x03:
#         addr_len = head[length]
#         length += 1
#         host = head[length:length + addr_len]
#         length = length + addr_len

#     else:
#         raise BadShadowHeader

#     port = struct.unpack('!H', head[length:length + 2])
#     length += 2

#     return host, port[0], length


async def cipher_relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cryptor: aes_256_cfb_Cyptor):
    while not reader.at_eof():
        data: bytes = await reader.read(2048)
        logging.debug(f'收到{len(data)}字节数据')
        writer.write(cryptor.cipher(data))
        await writer.drain()
        logging.debug(f'发送{len(data)}字节加密数据')


async def decipher_relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cryptor: aes_256_cfb_Cyptor):
    while not reader.at_eof():
        data: bytes = await reader.read(2048)
        logging.debug(f'收到{len(data)}字节加密数据')
        writer.write(cryptor.decipher(data))
        await writer.drain()
        logging.debug(f'发送{len(data)}字节数据')


def test_shadow(addr):
    origin_host, origin_port = addr

    head = make_shadow_head(addr)
    host, port, length = parse_shadow_head(head)

    assert len(head) == length
    assert to_bytes(origin_host) == host
    assert origin_port == port


if __name__ == "__main__":
    test_shadow((b'www.baidu.com', 443))
    test_shadow((inet_pton(AF_INET, '202.204.48.66'), 80))
    test_shadow((inet_pton(AF_INET6, '::ff'), 10230))
