# import asyncio
import trollius

from pyslp.slptool import SLPClient


if __name__ == '__main__':
    # loop = asyncio.get_event_loop()
    loop = trollius.get_event_loop()
    ip_addrs = ['127.0.0.1']
    slp_client = SLPClient(ip_addrs=ip_addrs)
    service_type = 'service:test'
    url = 'service:test://test.com'

    loop.run_until_complete(
        slp_client.register(
            service_type=service_type,
            lifetime=15,
            url=url,
            attr_list=''
        )
    )
    print('{} - service is registered successfully'.format(url))

    url_entries = loop.run_until_complete(
        slp_client.findsrvs(service_type=service_type)
    )
    print('findsrvs for {} - {}'.format(service_type, url_entries))

    attr_list = loop.run_until_complete(
        slp_client.findattrs(url=url)
    )
    print('findattrs for {} - {}'.format(url, attr_list))

    loop.run_until_complete(
        slp_client.deregister(url=url)
    )
    print('{} - service is deregistered successfully'.format(url))