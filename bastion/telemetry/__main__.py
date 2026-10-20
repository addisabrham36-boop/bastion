'''Telemetry package entrypoint.
Runs the TelemetryWorker using Redis and OpenSearch clients configured via environment variables.
'''

import asyncio
import os
import logging

from redis.asyncio import Redis
from opensearchpy import OpenSearch, RequestsHttpConnection

from .worker import TelemetryWorker

logger = logging.getLogger('bastion.telemetry')


def get_redis_client() -> Redis:
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    return Redis.from_url(redis_url)


def get_opensearch_client() -> OpenSearch:
    # Basic OpenSearch client; TLS verification can be disabled via OPENSEARCH_VERIFY_TLS.
    url = os.getenv('OPENSEARCH_URL', 'http://localhost:9200')
    verify = os.getenv('OPENSEARCH_VERIFY_TLS', 'true').lower() != 'false'
    username = os.getenv('OPENSEARCH_USERNAME')
    password = os.getenv('OPENSEARCH_PASSWORD')
    http_auth = (username, password) if username and password else None
    use_ssl = url.startswith("https") or (not verify)
    return OpenSearch(
        hosts=[url],
        http_auth=http_auth,
        use_ssl=use_ssl,
        verify_certs=verify,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection,
    )


async def main() -> None:
    try:
        from ..opensearch_bootstrap import bootstrap
        verify = os.getenv('OPENSEARCH_VERIFY_TLS', 'true').lower() != 'false'
        await asyncio.to_thread(bootstrap, opensearch_url=os.getenv('OPENSEARCH_URL'), verify_tls=verify)
    except Exception as e:
        logger.warning('Bootstrap warning: %s', e)

    redis_client = get_redis_client()
    opensearch_client = get_opensearch_client()
    worker = TelemetryWorker(redis_client, opensearch_client)
    await worker.setup_consumer_group()
    logger.info('Telemetry worker started')
    try:
        while True:
            processed = await worker.process_batch()
            if processed == 0:
                await asyncio.sleep(1)
    except asyncio.CancelledError:
        logger.info('Telemetry worker cancelled, shutting down')
    finally:
        await redis_client.close()
        if hasattr(opensearch_client, 'transport'):
            opensearch_client.transport.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
