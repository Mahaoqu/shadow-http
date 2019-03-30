from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from selectors import DefaultSelector, EVENT_READ

class connection:
    
    S_INIT = 0
    S_REMOTE_CONNECT = 1
    S_ESTABLISHED = 2
    S_REMOTE_WRITE = 3
    S_LOCAL_WRITE = 4

    def __init__(self, local_sock):
        self.state = S_INIT
        self.local_sock = local_sock
        self.remote_sock = None

        selector.register(sock, EVENT_READ, on_local_read)

    def update_state(self, new_state):
        if new_state == self.S_ESTABLISHED:
            pass
            


def on_local_read(key, mask):
    s = key.fileobj
    conn = socketmap[s]
    if conn.state == connection.S_INIT:
        data = s.recv(10000)
        

    elif conn.state == connection.S_REMOTE_CONNECT:
        pass
    elif conn.state == connection.S_ESTABLISHED:
        pass
    else:
        raise "Error!"


# 套接字和连接的映射
socketmap = {}

def on_accept(listen_socket):
    newsocket = listen_socket.accept()
    c = connection(newsocket)
    socketmap[newsocket] = c

listen_socket = None   #正在监听的套接字

def main():
    sock = socket()
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind(address)
    sock.listen(5)
    listen_socket = sock 

    selector.register(sock, EVENT_READ, on_accept)
    try:
        while True:
            events = selector.select()
            print('return from select..')
            for key, mask in events:
                if key.fd == listen_socket:
                    key.data(key.fileobj)

                callback = key.data
                callback(key, mask)
    except KeyboardInterrupt:
        sock.close()

if __name__ == "__main__":
    main()