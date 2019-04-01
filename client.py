import argparse
import logging
import os
import pprint
import socket
import struct
import sys

import encypt


def check_python():
    '''
    检查Python版本。

    仅考虑支持Python3.4及以上版本。
    '''
    if sys.version_info < (3, 5):
        print('Sorry, Python 3.4 above required.')
        exit(1)


def get_config():
    '''
    返回命令行参数。

    获得本地监听端口，远程主机地址、端口号和密码。加密模式目前只支持aes-256-cfb，可以选择开启Verbose模式。
    '''
    parser = argparse.ArgumentParser(description='ShadowHTTP 客户端')
    parser.add_argument("-i", "--host", required=True,
                        help="Shadowhttp 服务器IP地址")
    parser.add_argument("-p", "--port", required=True,
                        type=int, help="Shadowhttp 服务器端口号")
    parser.add_argument("-l", "--local", type=int, default=3107,
                        help="本地 HTTP 代理服务器监听端口, 默认使用 3107")
    parser.add_argument("-c", "--password", required=True,
                        help="连接 Shadowhttp 服务器的密码")
    parser.add_argument(
        "-m", "--method", help="加密方法, 只支持 aes-256-cfb", default="aes-256-cfb")
    parser.add_argument("-v", "--verbose", action="store_true", help="开启日志输出")

    args = parser.parse_args()
    verbose = args.verbose

    # 开启日志输出
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level,
                        format='[%(asctime)s]%(levelname)-s: %(message)s',
                        datefmt='%H:%M:%S')

    return args


def to_bytes(s):
    if type(s) == str:
        return s.encode('utf-8')
    return s


def to_str(s):
    if type(s) == bytes:
        return s.decode('utf-8')
    return s


def main():
    check_python()
    args = get_config()

    ###########


if __name__ == "__main__":
    main()
