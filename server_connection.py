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
    # 等待本地套接字可读
    S_INIT = 0

    # 等待DNS连接状态
    S_WAIT_DNS = 1

    # 等待远程连接状态
    # 等待远程套接字可写，本地套接字可读
    S_REMOTE_CONNECT = 2

    # 连接已经建立状态
    # 等待远程套接字可读，本地套接字可读
    S_ESTABLISHED = 3

    statemap = {
        S_INIT: "S_INIT",
        S_WAIT_DNS: "S_WAIT_DNS",
        S_REMOTE_CONNECT: "S_REMOTE_CONNECT",
        S_ESTABLISHED: "S_ESTABLISHED"
    }

    BUF_SIZE = 4096

    count = 0

    def __init__(self, local_sock, local_addr, passwd):
        '''
        初始化连接的状态。

        应该由监听套接字的回调函数调用。
        '''
        self.state = None
        self.local_sock = local_sock
        self.local_addr = local_addr
        self.remote_sock = None
        self.remote_addr = None  # 远程服务器

        self.passwd = passwd

        self.cryptor = aes_256_cfb_Cyptor(to_bytes(passwd))  #加密器

        self.upstream_buffer = b''  # 从本地读，向远程写
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
            data = _recv_from_sock(self.local_sock)

            # 如果本地套接字提前终止，就销毁这个连接
            if not data:
                logging.warning("[{0}]远程连接{1}:{2}提前终止".format(
                    self.id, self.remote_addr[0], self.remote_addr[1]))
                self.destory()
                return

            # 解析Shadow头，得到远程地址
            # 并将剩余部分加入缓冲区
            try:
                self.remote_addr, head_length = parse_shadow_head(data)

            except:
                self.destory()
                return

            self.upstream_buffer += data[head_length:]

            # 假设返回的是IP地址...
            # 尝试连接远程套接字，并转换到等待远程连接状态。
            try:
                self.remote_sock.connect(self.remote_addr)  # 这里是从终端输入的地址
            except BlockingIOError:
                logging.debug("[{0}]尝试非阻塞连接远程服务器".format(self.id))

            self.update_state(self.S_REMOTE_CONNECT)

        def wdns_on_local_read(key, mask):
            pass

        def rconn_on_local_read(key, mask):
            '''
            本地可读，把读到的内容加入缓冲区的尾部
            '''
            self.upstream_buffer += _recv_from_sock(self.local_sock)

        def rconn_on_remote_write(key, mask):
            '''
            远程套接字变为可写，说明连接已经建立
            '''
            logging.info("[{0}]远程地址{1}:{2}连接成功...".format(
                self.id, self.remote_addr[0], self.remote_addr[1]))

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

            ciphered = self.cryptor.decipher(data)
            self.remote_sock.send(ciphered)
            logging.debug("[{0}]向远程服务器{1}:{2}发送{3}字节数据".format(
                self.id, self.remote_addr[0], self.remote_addr[1],
                len(ciphered)))

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

            deciphered = self.cryptor.cipher(data)
            x = self.local_sock.send(deciphered)
            logging.debug("[{0}]向本地服务器{1}:{2}发送{3}字节数据".format(
                self.id, self.local_addr[0], self.local_addr[1], x))

        if new_state == self.state:
            return

        if new_state == self.S_INIT:
            selector.register(self.local_sock, EVENT_READ, init_on_local_read)

        elif new_state == self.S_WAIT_DNS:
            selector.modify(self.local_sock, EVENT_READ, wdns_on_local_read)

        elif new_state == self.S_REMOTE_CONNECT:
            selector.modify(self.local_sock, EVENT_READ, rconn_on_local_read)
            selector.register(self.remote_sock, EVENT_WRITE,
                              rconn_on_remote_write)

        elif new_state == self.S_ESTABLISHED:
            selector.modify(self.local_sock, EVENT_READ,
                            establised_on_local_read)
            selector.modify(self.remote_sock, EVENT_READ,
                            establised_on_remote_read)

        self.state = new_state
        logging.debug("[{0}]切换到状态{1}".format(self.id,
                                             self.statemap[self.state]))

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
