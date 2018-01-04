# import asyncio
import trollius

from pyslp.slpd import create_slpd


if __name__ == '__main__':
    # loop = asyncio.get_event_loop()
    loop = trollius.get_event_loop()
    ip_addrs = ['127.0.0.1']
    loop.run_until_complete(create_slpd(ip_addrs))
    loop.run_forever()