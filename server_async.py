import asyncio
import logging
import socket
import struct

from common import cipher_relay, decipher_relay, parse_shadow_head, to_bytes
from encypt import aes_256_cfb_Cyptor


async def listen(args):

    async def connection(local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter):
        try:
            # 解密后，异步解析头部，此处可能需要解析DNS，之后截取剩下的头部
            cipher = aes_256_cfb_Cyptor(to_bytes(args.password))
            ciphered_data = await local_reader.read(2048)
            data = cipher.decipher(ciphered_data)
            host, port, head_length = await parse_shadow_head(data)
            data = data[head_length:]

            # 建立远程连接
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
            logging.info(f'连接远程服务器{host}:{port}成功')

            if data:
                remote_writer.write(data)
                logging.debug(f'发送{len(data)}字节数据')

            # 开启双向连接
            await asyncio.gather(
                decipher_relay(local_reader, remote_writer, cipher),
                cipher_relay(remote_reader, local_writer, cipher)
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
