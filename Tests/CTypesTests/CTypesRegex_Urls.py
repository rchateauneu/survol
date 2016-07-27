import sys
import ctypes_scanner

pidint = int(sys.argv[1])

toto = ctypes_scanner.GetRegexMatches(pidint,"http://[a-zA-Z_0-9\.]*")

print(toto)
print(len(toto))
