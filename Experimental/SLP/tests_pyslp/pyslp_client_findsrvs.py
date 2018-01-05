import asyncio

from pyslp.slptool import SLPClient


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    ip_addrs = ['127.0.0.1']
    slp_client = SLPClient(ip_addrs=ip_addrs)
    service_type = 'service:test'
    url = 'service:test://test.com'

    url_entries = loop.run_until_complete(
        slp_client.findsrvs(service_type=service_type)
    )
    print('findsrvs for {} - {}'.format(service_type, url_entries))
