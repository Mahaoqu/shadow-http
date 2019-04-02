import logging
import struct
from selectors import EVENT_READ, EVENT_WRITE, DefaultSelector
from socket import (AF_INET, AF_INET6, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET,
                    SOL_TCP, TCP_NODELAY, SHUT_WR, inet_pton, socket)

from common import is_ip, make_shadow_head, parse_http, to_bytes, to_str
from encypt import aes_256_cfb_Cyptor

selector = DefaultSelector()


class Connection:
    '''
    表示隧道客户端的一个双向套接字连接。
    '''
    # 初始状态
    # 等待本地套接字的读
    S_INIT = 0

    # 等待远程连接状态
    # 等待远程套接字的写，本地套接字的读
    S_REMOTE_CONNECT = 1

    # 连接已经建立状态
    # 等待远程套接字的读，本地套接字的读
    S_ESTABLISHED = 2

    # 向远程写状态
    # 等待远程套接字的写，本地套接字的读
    S_REMOTE_WRITE = 3

    # 向本地写状态
    # 等待远程套接字的读，本地套接字的写
    S_LOCAL_WRITE = 4

    statemap = {
        S_INIT: "S_INIT",
        S_REMOTE_CONNECT: "S_REMOTE_CONNECT",
        S_ESTABLISHED: "S_ESTABLISHED",
        S_REMOTE_WRITE: "S_REMOTE_WRITE",
        S_LOCAL_WRITE: "S_LOCAL_WRITE"
    }

    BUF_SIZE = 4096

    count = 0

    def __init__(self, local_sock, local_addr, passwd, remote_addr):
        '''
        初始化连接的状态。

        应该由监听套接字的回调函数调用。
        '''
        self.state = None
        self.local_sock = local_sock
        self.local_addr = local_addr
        self.remote_sock = None
        self.remote_addr = remote_addr  # 隧道服务器

        self.dst_addr = None  # 远程服务器

        self.passwd = passwd

        self.cryptor = aes_256_cfb_Cyptor(to_bytes(passwd))

        self.upstream_buffer = b''   # 从本地读，向远程写
        self.downstream_buffer = b''  # 从远程读，向本地写

        self.local_closed = False
        self.remote_closed = False
        self.id = Connection.count
        Connection.count = Connection.count + 1

        self.update_state(self.S_INIT)

    def update_state(self, new_state):
        '''
        更新连接的状态。

        对每一个状态，为套接字注册相应的回调函数。
        '''
        def init_on_local_read(key, mask):
            data = self.local_sock.recv(1024)

            # 如果本地套接字提前终止，就销毁这个连接
            if not data:
                logging.warning("[{0}]远程连接{1}:{2}提前终止".format(
                    self.id, self.remote_addr[0], self.remote_addr[1]))
                self.destory()
                return

            # 将已读到的内容加入缓冲区
            self.upstream_buffer += data

            # 如果读到完整的HTTP请求，就解析它，获得远程地址和端口。
            # 尝试连接远程套接字，并转换到等待远程连接状态。
            if b'\r\n\r\n' in self.upstream_buffer:
                try:
                    self.dst_addr = parse_http(
                        self.upstream_buffer)  # (ip_addr, port)
                    logging.info("[{0}]本地请求连接到 {1}:{2}".format(
                        self.id, self.dst_addr[0].decode('utf-8'), self.dst_addr[1]))
                    self.remote_sock = socket()
                    self.remote_sock.setblocking(False)
                    self.remote_sock.setsockopt(SOL_TCP, TCP_NODELAY, 1)
                    try:
                        self.remote_sock.connect(
                            self.remote_addr)  # 这里是从终端输入的地址
                    except BlockingIOError:
                        logging.debug("[{0}]尝试非阻塞连接服务器".format(self.id))

                    self.upstream_buffer = b''
                    self.update_state(self.S_REMOTE_CONNECT)

                # 如果解析失败就销毁这个连接
                except OSError:
                    logging.error("[{0}]解析本地连接HTTP隧道头失败".format(self.id))
                    self.destory()

        def rconn_on_local_read(key, mask):
            '''
            本地可读，说明本地出现了错误，此时销毁这个连接。
            '''
            _ = self.local_sock.recv(1024)
            logging.debug("[{0}]本地连接{1}:{2}提前断开连接".format(self.id,
                                                          self.local_addr[0], self.local_addr[1]))

            self.destory()

        def rconn_on_remote_write(key, mask):
            '''
            远程套接字变为可写，说明连接已经建立
            '''
            shadow_head = make_shadow_head(self.dst_addr)
            c_head = self.cryptor.cipher(shadow_head)

            try:
                self.remote_sock.send(c_head)

            # 连接失败，此时发送会失败
            except BrokenPipeError:
                logging.debug("[{0}]远程连接{1}:{2}失败".format(
                    self.id, self.remote_addr[0], self.remote_addr[1]))
                self.destory()
                return

            logging.info("[{0}]远程地址{1}:{2}连接成功...".format(
                self.id, self.remote_addr[0], self.remote_addr[1]))

            self.local_sock.send(
                b'HTTP/1.1 200 Connection Established\r\n\r\n')

            logging.debug("[{0}]向远程服务器发送{1}:{2} {3}字节Shadow头".format(
                self.id, self.remote_addr[0], self.remote_addr[1], len(c_head)))
            self.update_state(self.S_ESTABLISHED)

        def establised_on_local_read(key, mask):
            data = self._recv_from_sock(self.local_sock)

            if data is None:
                return

            if not data:
                logging.info("[{0}]本地关闭连接".format(self.id))
                if self.remote_closed == True:
                    self.destory()
                    return
                self.remote_sock.shutdown(SHUT_WR)
                selector.unregister(self.local_sock)

                self.local_closed = True
                return

            ciphered = self.cryptor.cipher(data)
            self.remote_sock.send(ciphered)
            logging.debug("[{0}]向远程服务器{1}:{2}发送{3}字节数据".format(
                self.id, self.remote_addr[0], self.remote_addr[1], len(ciphered)))

        def establised_on_remote_read(key, mask):
            data = self._recv_from_sock(self.remote_sock)

            # 出现异常，已经被销毁
            if data is None:
                return

            if not data:
                logging.info("[{0}]远程服务器关闭连接".format(self.id))
                if self.local_closed == True:
                    self.destory()
                    return
                self.local_sock.shutdown(SHUT_WR)
                selector.unregister(self.remote_sock)

                self.remote_closed = True
                return

            deciphered = self.cryptor.decipher(data)
            x = self.local_sock.send(deciphered)
            logging.debug("[{0}]向本地服务器{1}:{2}发送{3}字节数据".format(
                self.id, self.local_addr[0], self.local_addr[1], x))

        def lwrite_on_local_write(key, mask):
            pass

        def lwrite_on_remote_read(key, mask):
            pass

        def rwrite_on_local_read(key, mask):
            pass

        def rwrite_on_remote_write(key, mask):
            pass

        if new_state == self.state:
            return

        if new_state == self.S_INIT:
            selector.register(self.local_sock, EVENT_READ, init_on_local_read)

        elif new_state == self.S_REMOTE_CONNECT:
            selector.modify(self.local_sock, EVENT_READ, rconn_on_local_read)
            selector.register(self.remote_sock,
                              EVENT_WRITE, rconn_on_remote_write)

        elif new_state == self.S_ESTABLISHED:
            selector.modify(self.local_sock, EVENT_READ,
                            establised_on_local_read)
            selector.modify(self.remote_sock, EVENT_READ,
                            establised_on_remote_read)

        elif new_state == self.S_REMOTE_WRITE:
            selector.modify(self.local_sock, EVENT_READ, rwrite_on_local_read)
            selector.modify(self.remote_sock, EVENT_WRITE,
                            rwrite_on_remote_write)

        elif new_state == self.S_LOCAL_WRITE:
            selector.modify(self.remote_sock, EVENT_READ,
                            lwrite_on_remote_read)
            selector.modify(self.local_sock, EVENT_WRITE,
                            lwrite_on_local_write)

        self.state = new_state
        logging.debug("[{0}]切换到状态{1}".format(
            self.id, self.statemap[self.state]))

    def _recv_from_sock(self, sock):
        if sock == self.local_sock:
            addr = self.local_addr
        else:
            addr = self.remote_addr

        try:
            data = sock.recv(4086)

        # 接受时被对方重置连接
        except ConnectionResetError:
            logging.error("[{0}]连接已经被 {1}:{2} 重置".format(
                self.id, addr[0], addr[1]))
            self.destory()
            return

        else:
            # 读到EOF时不写日志
            if data:
                logging.debug("[{0}]从 {1}:{2} 收到{3}字节数据".format(
                    self.id, addr[0], addr[1], len(data)))
            return data

    def destory(self):
        '''
        销毁连接。

        分别销毁对应的套接字。并在事件循环中删除。
        '''
        logging.info("[{0}]连接已被销毁".format(self.id))

        # 由于之前可能会提前解除注册.. 这里捕获这个异常。
        # TODO: 重构关闭和解除注册的逻辑
        if self.local_sock:
            try:
                selector.unregister(self.local_sock)
            except KeyError:
                pass
            self.local_sock.close()

        if self.remote_sock:
            try:
                selector.unregister(self.remote_sock)
            except KeyError:
                pass
            self.remote_sock.close()


def on_new_conn(args):

    server_addr = args.host, args.port
    passwd = args.password

    def on_accept(key, mask):
        '''
        有新连接到来时调用的函数。

        建立一个新连接对象，并在连接表中注册。
        '''
        new_socket, addr = key.fileobj.accept()
        Connection(new_socket, addr, passwd, server_addr)
        logging.debug("建立新的连接请求，本地{0}:{1}".format(addr[0], addr[1]))

    return on_accept


def main(args):
    sock = socket()
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind(('', args.local))
    sock.listen(5)

    on_accept = on_new_conn(args)  # 设定当连接
    selector.register(sock, EVENT_READ, on_accept)
    try:
        while True:
            events = selector.select()  # 程序会在这里阻塞等待事件发生
            for key, mask in events:
                callback = key.data
                callback(key, mask)

    except KeyboardInterrupt:
        sock.close()


if __name__ == "__main__":
    class Data:
        def __init__(self):
            self.local = 7301
            self.host = '127.0.0.1'
            self.port = 8888
            self.password = '1234567'
    main(Data())
