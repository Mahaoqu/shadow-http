from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE

selector = DefaultSelector()


class connection:
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

    def __init__(self, local_sock, local_addr):
        '''
        初始化连接的状态。

        应该由监听套接字的回调函数调用。
        '''
        self.state = None
        self.local_sock = local_sock
        self.local_addr = local_addr
        self.remote_sock = None

        self.upstream_buffer = []   # 从本地读，向远程写
        self.downstream_buffer = []  # 从远程读，向本地写

        self.update_state(self.S_INIT)
        self.count = 0

    def update_state(self, new_state):
        '''
        更新连接的状态。

        对每一个状态，为套接字注册相应的回调函数。
        '''
        def init_on_local_read(key, mask):
            pass

        def rconn_on_local_read(key, mask):
            pass

        def rconn_on_remote_write(key, mask):
            pass

        def establised_on_local_read(key, mask):
            pass

        def establised_on_remote_read(key, mask):
            pass

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
            selector.register(self.remote_sock, EVENT_READ |
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

    def destory(self):
        '''
        销毁连接。

        分别销毁对应的套接字。并在事件循环中删除。
        '''
        print(f'destoryed socket {id(self)}')
        if self.local_sock:
            selector.unregister(self.local_sock)
            self.local_sock.close()

        if self.remote_sock:
            selector.unregister(self.remote_sock)
            self.remote_sock.close()


conns = []


def on_accept(key, mask):
    '''
    有新连接到来时调用的函数。

    建立一个新连接对象，并在连接表中注册。
    '''
    new_socket, addr = key.fileobj.accept()
    conns.append(connection(new_socket, addr))


def main(address):
    sock = socket()
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(5)

    selector.register(sock, EVENT_READ, on_accept)
    try:
        while True:
            events = selector.select()
            for key, mask in events:
                callback = key.data
                callback(key, mask)

    except KeyboardInterrupt:
        sock.close()


if __name__ == "__main__":
    main(("127.0.0.1", 9999))
