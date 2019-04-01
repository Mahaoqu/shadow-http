from socket import AF_INET, AF_INET6, inet_pton

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

'''HTTP协议的处理函数。只解析Connect方法'''


def is_total_http(buffer):
    return b'CONNECT www.google.com:443 HTTP/1.1\n' in buffer


def parse_http(connection):
    return (None, None)