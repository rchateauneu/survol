import sys
import readelf

finam = "/usr/lib64/libnss_dns-2.21.so"
file = open(finam, 'rb')

readelf = readelf.ReadElf(file, sys.stdout)

readelf.display_symbol_tables()

