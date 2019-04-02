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

def is_total_http(buffer):
    return b'CONNECT www.google.com:443 HTTP/1.1\n' in buffer


def parse_http(connection):
    return ('172.217.160.78', 443)

def make_shadow_head(addr):
    print(addr)
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
