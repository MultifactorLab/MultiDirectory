"""Main MiltiDirecory module."""

import asyncio
import socket
import ssl
from contextlib import asynccontextmanager
from traceback import format_exc

from loguru import logger
from pydantic import ValidationError

from config import Settings
from ldap_protocol import LDAPRequestMessage, Session
from models.database import create_session_factory

logger.add(
    "logs/file_{time:DD-MM-YYYY}.log",
    retention="10 days",
    rotation="1d",
    colorize=False)


class PoolClientHandler:
    """Async client handler.

    Don't need to wait until client sends
    request or do not need to wait until response formed.
    Can handle requests for a single client asynchronously.

    No __init__ method, as `start_server`
    uses callable object for a single connection.
    """

    def __init__(
        self,
        settings: Settings,
        num_workers: int = 3,
    ):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers
        self.settings = settings
        self.AsyncSessionFactory = create_session_factory(self.settings)

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Create session, queue and start message handlers concurrently."""
        ldap_session = Session(reader, writer)

        if self.settings.USE_CORE_TLS:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(
                self.settings.SSL_CERT, self.settings.SSL_KEY)
            logger.info(
                f"Starting TLS for {ldap_session.addr}, ciphers loaded")
            await ldap_session.writer.start_tls(ssl_context)
            logger.success(f"Successfully started TLS for {ldap_session.addr}")

        handle = asyncio.create_task(self.handle_responses(ldap_session))

        try:
            await asyncio.gather(self.handle_request(ldap_session), handle)
        except RuntimeError:
            logger.error(
                f"The connection {ldap_session.addr} raised {format_exc()}")
        except ConnectionAbortedError:
            logger.info(
                'Connection termination initialized '
                f'by a client {ldap_session.addr}')
        finally:
            ldap_session.writer.close()
            await ldap_session.writer.wait_closed()
            await handle
            await ldap_session.queue.join()
            logger.success(f'Connection {ldap_session.addr} normally closed')

    @staticmethod
    async def handle_request(ldap_session: Session):
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        while True:
            data = await ldap_session.reader.read(4096)

            if not data:
                raise ConnectionAbortedError(
                    'Connection terminated by client')

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (
                ValidationError, IndexError,
                KeyError, ValueError,
            ) as err:
                logger.warning(f'Invalid schema {format_exc()}')

                ldap_session.writer.write(
                    LDAPRequestMessage.from_err(data, err).encode())
                await ldap_session.writer.drain()

            except Exception as err:
                logger.error(f'Unexpected {format_exc()}')
                raise RuntimeError('Unexpected exception') from err

            else:
                await ldap_session.queue.put(request)

    @asynccontextmanager
    async def create_session(self):
        """Create session for request."""
        async with self.AsyncSessionFactory() as session:
            yield session

    async def handle_single_response(self, ldap_session: Session):
        """Get message from queue and handle it."""
        while True:
            message = await ldap_session.queue.get()
            logger.info(f"\nFrom: {ldap_session.addr!r}\nRequest: {message}\n")

            async with self.create_session() as session:
                async for response in message.create_response(
                        ldap_session, session):
                    logger.info(
                        f"""\nTo: {ldap_session.addr!r}\n
                        Response: {response}"""[:3000])

                    ldap_session.writer.write(response.encode())
                    await ldap_session.writer.drain()

    async def handle_responses(self, ldap_session: Session):
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        await asyncio.gather(
            *[self.handle_single_response(ldap_session)
                for _ in range(self.num_workers)])

    async def get_server(self) -> asyncio.base_events.Server:
        """Get async server."""
        return await asyncio.start_server(
            self, str(self.settings.HOST), self.settings.PORT,
            flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
        )

    @staticmethod
    async def run_server(server: asyncio.base_events.Server):
        """Run server."""
        async with server:
            await server.serve_forever()

    @staticmethod
    def log_addrs(server: asyncio.base_events.Server):  # noqa
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f'Server on {addrs}')

    async def start(self):
        """Run and log tcp server."""
        server = await self.get_server()
        self.log_addrs(server)
        try:
            await self.run_server(server)
        finally:
            server.close()


if __name__ == '__main__':
    asyncio.run(PoolClientHandler(Settings()).start())
