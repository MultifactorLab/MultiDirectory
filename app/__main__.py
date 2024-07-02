"""Main MiltiDirecory module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import argparse
import asyncio
import base64
import json
import math
import os
import socket
import ssl
from contextlib import asynccontextmanager
from io import BytesIO
from ipaddress import IPv4Address
from tempfile import NamedTemporaryFile
from traceback import format_exc
from typing import AsyncIterator, cast

import uvloop
from loguru import logger
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from ldap_protocol import LDAPRequestMessage, Session
from ldap_protocol.messages import LDAPMessage, LDAPResponseMessage
from models.database import create_session_factory
from models.ldap3 import NetworkPolicy

log = logger.bind(name='ldap')

log.add(
    "logs/ldap_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'ldap',
    retention="10 days",
    rotation="1d",
    colorize=False)


infinity = cast(int, math.inf)


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
        rcv_size: int = 1024,
    ):
        """Set workers number for single client concurrent handling."""
        self.num_workers = num_workers
        self.settings = settings
        self.AsyncSessionFactory = create_session_factory(self.settings)
        self._size = rcv_size

        if settings.DEBUG:
            self.req_log = self._req_log_full
            self.rsp_log = self._resp_log_full
        else:
            self.req_log = self.rsp_log = self._log_short

        self.ssl_context = None

        if self.settings.USE_CORE_TLS:
            with (
                NamedTemporaryFile('w+') as certfile,
                NamedTemporaryFile('w+') as keyfile,
            ):
                if os.path.exists('/certs/cert.pem') and os.path.exists(
                        '/certs/privkey.pem'):
                    cert_name = self.settings.SSL_CERT
                    key_name = self.settings.SSL_KEY
                    log.success('Found existing cert and key, loading...')

                else:
                    cert, key = self._read_acme_cert()
                    certfile.write(cert)
                    keyfile.write(key)

                    certfile.seek(0)
                    keyfile.seek(0)

                    cert_name = certfile.name
                    key_name = keyfile.name

                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                self.ssl_context.load_cert_chain(cert_name, key_name)

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Create session, queue and start message handlers concurrently."""
        async with Session(
                reader, writer, settings=self.settings) as ldap_session:
            if (policy := await self.get_policy(ldap_session.ip)) is not None:
                ldap_session.policy = policy
            else:
                log.warning(f"Whitelist violation from {ldap_session.addr}")
                return

            try:
                await asyncio.gather(
                    self._handle_request(ldap_session),
                    self._handle_responses(ldap_session),
                )
            except RuntimeError:
                log.exception(f"The connection {ldap_session.addr} raised")
            except ConnectionAbortedError:
                pass

    async def get_policy(self, ip: IPv4Address) -> NetworkPolicy | None:
        """Get network policies."""
        async with self.create_session() as session:
            return await session.scalar((  # noqa
                select(NetworkPolicy)
                .filter_by(enabled=True)
                .options(selectinload(NetworkPolicy.groups))
                .filter(
                    text(':ip <<= ANY("Policies".netmasks)').bindparams(ip=ip))
                .order_by(NetworkPolicy.priority.asc())
                .limit(1)
            ))

    async def recieve(self, reader: asyncio.StreamReader) -> bytes:
        """Read N packets by 1kB."""
        buffer = BytesIO()

        while True:
            buffer.write(await reader.read(self._size))

            actual_size = buffer.getbuffer().nbytes
            computed_size = self._compute_ldap_message_size(buffer.getvalue())

            if reader.at_eof() or actual_size >= computed_size:
                break

        return buffer.getvalue()

    @staticmethod
    def _read_acme_cert() -> tuple[str, str]:
        if not os.path.exists('/certs/acme.json'):
            log.critical('Cannot load SSL cert for MultiDirectory')
            raise

        with open('/certs/acme.json') as certfile:
            data = json.load(certfile)

        try:
            domain = data['md-resolver'][
                'Certificates'][0]['domain']['main']
        except (KeyError, IndexError):
            log.critical('Cannot load SSL cert for MultiDirectory')
            raise

        log.info(f'loaded cert for {domain}')

        cert = data['md-resolver']['Certificates'][0]['certificate']
        key = data['md-resolver']['Certificates'][0]['key']

        cert = base64.b64decode(cert.encode('ascii')).decode()
        key = base64.b64decode(key.encode('ascii')).decode()

        return cert, key

    @staticmethod
    def _compute_ldap_message_size(data: bytes) -> int:
        """Compute LDAP Message size according to BER definite length rules.

        returns infinity if too few data to compute message length.

        BER definite length - short form.
        Highest bit of byte 1 is 0, message length is in the last 7 bits -
            Value can be up to 127 bytes long

        BER definite length - long form.
        Highest bit of byte 1 is 1, last 7 bits
        counts the number of following octets containing the value length.

        source:
        https://github.com/cannatag/ldap3/blob/dev/ldap3/strategy/base.py#L455

        :param bytes data: body
        :return int: actual size
        """
        if len(data) > 2:
            if data[1] <= 127:  # short
                return data[1] + 2

            bytes_length = data[1] - 128  # long
            if len(data) >= bytes_length + 2:
                value_length = 0
                cont = bytes_length
                for byte in data[2:2 + bytes_length]:
                    cont -= 1
                    value_length += byte * (256 ** cont)
                return value_length + 2 + bytes_length
        return infinity

    async def _handle_request(self, ldap_session: Session) -> None:
        """Create request object and send it to queue.

        :raises ConnectionAbortedError: if client sends empty request (b'')
        :raises RuntimeError: reraises on unexpected exc
        """
        while True:
            data = await self.recieve(ldap_session.reader)
            # data = await ldap_session.reader.read(1500)

            if not data:
                raise ConnectionAbortedError(
                    'Connection terminated by client')

            try:
                request = LDAPRequestMessage.from_bytes(data)

            except (ValidationError, IndexError, KeyError, ValueError) as err:
                log.warning(f'Invalid schema {format_exc()}')

                ldap_session.writer.write(
                    LDAPRequestMessage.from_err(data, err).encode())
                await ldap_session.writer.drain()

            except Exception as err:
                raise RuntimeError(err) from err

            else:
                await ldap_session.queue.put(request)

    @asynccontextmanager
    async def create_session(self) -> AsyncIterator[AsyncSession]:
        """Create session for request."""
        async with self.AsyncSessionFactory() as session:
            yield session
            await session.commit()

    @staticmethod
    def _req_log_full(addr: str, msg: LDAPRequestMessage) -> None:
        log.debug(
            f"\nFrom: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}\n")

    @staticmethod
    def _resp_log_full(addr: str, msg: LDAPResponseMessage) -> None:
        log.debug(
            f"\nTo: {addr!r}\n{msg.name}[{msg.message_id}]: "
            f"{msg.model_dump_json()}"[:3000])

    @staticmethod
    def _log_short(addr: str, msg: LDAPMessage) -> None:
        log.info(f"\n{addr!r}: {msg.name}[{msg.message_id}]\n")

    async def _handle_single_response(self, ldap_session: Session) -> None:
        """Get message from queue and handle it."""
        while True:
            try:
                message = await ldap_session.queue.get()
                self.req_log(ldap_session.addr, message)

                async with self.create_session() as session:
                    async for response in message.create_response(
                            ldap_session, session):
                        self.rsp_log(ldap_session.addr, response)
                        ldap_session.writer.write(response.encode())
                        await ldap_session.writer.drain()

                ldap_session.queue.task_done()
            except Exception as err:
                raise RuntimeError(err) from err

    async def _handle_responses(self, ldap_session: Session) -> None:
        """Create pool of workers and apply handler to it.

        Spawns (default 5) workers,
        then every task awaits for queue object,
        cycle locks until pool completes at least 1 task.
        """
        await asyncio.gather(
            *[self._handle_single_response(ldap_session)
                for _ in range(self.num_workers)])

    async def _get_server(self) -> asyncio.base_events.Server:
        """Get async server."""
        return await asyncio.start_server(
            self, str(self.settings.HOST), self.settings.PORT,
            flags=socket.MSG_WAITALL | socket.AI_PASSIVE,
            ssl=self.ssl_context,
        )

    @staticmethod
    async def _run_server(server: asyncio.base_events.Server) -> None:
        """Run server."""
        async with server:
            await server.serve_forever()

    @staticmethod
    def log_addrs(server: asyncio.base_events.Server) -> None:  # noqa
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        log.info(f'Server on {addrs}')

    async def start(self) -> None:
        """Run and log tcp server."""
        server = await self._get_server()
        try:
            await self._run_server(server)
        finally:
            server.close()
            await server.wait_closed()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='MultiDirectory',
        description='Run ldap server')
    parser.add_argument(
        '--loop',
        choices=['asyncio', 'uvloop'],
        default='asyncio',
        required=True,
    )
    args = parser.parse_args()

    settings = Settings()
    log.info(f'Started LDAP server with {args.loop}')

    async def _servers() -> None:
        await asyncio.gather(
            PoolClientHandler(settings).start(),
            PoolClientHandler(settings.get_copy_4_tls()).start(),
        )

    if args.loop == 'uvloop':
        with asyncio.Runner(
                loop_factory=uvloop.new_event_loop,
                debug=settings.DEBUG) as runner:
            runner.run(_servers())
    elif args.loop == 'asyncio':
        asyncio.run(_servers(), debug=settings.DEBUG)
