import argparse
import logging
import os
import socket
import struct
import sys

import server_async


def check_python():
    '''
    检查Python版本。

    仅支持Python3.7及以上版本。
    '''
    if sys.version_info < (3, 7):
        print('抱歉，仅支持Python 3.7 及以上版本.')
        exit(1)


def get_config():
    '''
    返回命令行参数。

    获得本地监听端口、密码。加密模式目前只支持aes-256-cfb，可以选择开启Verbose模式。
    '''
    parser = argparse.ArgumentParser(description='ShadowHTTP 服务器')
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


def main():
    check_python()
    args = get_config()
    server_async.main(args)


if __name__ == "__main__":
    main()
