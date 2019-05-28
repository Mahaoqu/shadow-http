import asyncio
import logging
import socket

from common import (BadHttpHeader, NoAcceptableMethods, cipher_relay,
                    decipher_relay, make_shadow_head, parse_http, to_bytes)
from encypt import aes_256_cfb_Cyptor


async def listen(args):

    async def connection(local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter):
        try:
            line = await local_reader.readuntil(b'\r\n\r\n')
            logging.debug(f'收到连接请求...')
            dst_addr = parse_http(line)

            # 建立远程连接
            remote_reader, remote_writer = await asyncio.open_connection(args.host, args.port)
            logging.info(f'连接远程服务器{args.host}:{args.port}成功')

            # 向本地回复
            local_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await local_writer.drain()

            # 向远程发送Shadow头部
            cipher = aes_256_cfb_Cyptor(to_bytes(args.password))
            head = cipher.cipher(make_shadow_head(dst_addr))
            remote_writer.write(head)
            await remote_writer.drain()
            logging.debug(
                f'向远程发送{len(head)}字节连接请求 {dst_addr[0]}:{dst_addr[1]}')

            # 开启双向连接
            await asyncio.gather(
                cipher_relay(local_reader, remote_writer, cipher),
                decipher_relay(remote_reader, local_writer, cipher)
            )
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            logging.exception(e)
        finally:
            local_writer.close()
            remote_writer.close()
            logging.info('连接已关闭')

    server = await asyncio.start_server(connection, port=args.local)
    logging.info(f'监听 {server.sockets[0].getsockname()}')

    async with server:
        await server.serve_forever()


def main(args):
    asyncio.run(listen(args))
