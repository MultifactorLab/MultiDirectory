"""Test client for LDAP server."""

from ldap3 import Connection, Server
from loguru import logger


def run_client():
    server = Server('127.0.0.1:389')
    conn = Connection(server, 'username', 'password', version=3)
    logger.info('connecting')
    try:
        conn.bind()
    except Exception as exc:
        logger.error(f'failed {exc}')
    else:
        search_res = conn.search('o=test', '(objectclass=*)')
        logger.info(f'OK {search_res}')
