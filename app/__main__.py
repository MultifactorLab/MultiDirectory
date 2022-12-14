"""Main MiltiDirecory module."""

import asyncio
from traceback import format_exc

from asyncio_pool import AioPool
from loguru import logger
from pydantic import ValidationError

from config import settings
from ldap import LDAPRequestMessage, Session


class PoolClient:
    """Async client handler.

    Don't need to wait until client sends
    request or do not need to wait until response formed.
    Can handle requests for a single client asynchronously.

    No __init__ method, as `start_server`
    uses callable object for a single connection.
    """

    def __init__(self, num_workers: int = 3):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Create session, queue and start message handlers concurrently."""
        self.session = Session()
        self.queue: asyncio.Queue[LDAPRequestMessage] = asyncio.Queue()
        self.reader = reader
        self.writer = writer
        self.addr = writer.get_extra_info('peername')
        try:
            await asyncio.gather(
                self.handle_request(),
                self.handle_responses(),
            )
        except RuntimeError:
            logger.error(f"The connection {self.addr} raised {format_exc()}")
        except ConnectionAbortedError:
            writer.close()

    async def handle_request(self):
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        while True:
            data = await self.reader.read(4096)
            if not data:
                raise ConnectionAbortedError('Connection terminated by client')

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (ValidationError, IndexError, KeyError, ValueError) as err:
                logger.warning(f'Invalid schema {format_exc()}')

                self.writer.write(
                    LDAPRequestMessage.from_err(data, err).encode())
                await self.writer.drain()

            except Exception as err:
                raise RuntimeError('Unexpected exception') from err

            else:
                await self.queue.put(request)

    async def handle_single_response(self):
        """Get message from queue and handle it."""
        message = await self.queue.get()

        async for response in message.create_response(self.session):
            logger.info(
                f"\nFrom: {self.addr!r}"
                f"\nRequest: {message}\nResponse: {response}")

            self.writer.write(response.encode())
            await self.writer.drain()

    async def handle_responses(self):
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        async with AioPool(self.num_workers) as pool:
            while True:
                await pool.spawn(self.handle_single_response())


async def main():
    """Start server and debug client."""
    server = await asyncio.start_server(PoolClient(), str(settings.HOST), 389)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f'Server on {addrs}')
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
