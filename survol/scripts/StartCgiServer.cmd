REM Helper script for development
REM Needed

REM This works on 192.168.0.14 WIn7 but not on Win10
REM It displays:
REM Server address=192.168.0.14
REM Opening rchateau-HP:8000
python survol\scripts\cgiserver.py -b webbrowser

REM From win10 192.168.0.14, here is the result of the command IPCONFIG:
REM Ethernet adapter Npcap Loopback Adapter:
REM
REM    Connection-specific DNS Suffix  . :
REM    Link-local IPv6 Address . . . . . : fe80::b971:331b:4653:4afb%10
REM    Autoconfiguration IPv4 Address. . : 169.254.74.251
REM    Subnet Mask . . . . . . . . . . . : 255.255.0.0
REM    Default Gateway . . . . . . . . . :
REM
REM Wireless LAN adapter WiFi:
REM
REM    Connection-specific DNS Suffix  . :
REM    Link-local IPv6 Address . . . . . : fe80::b110:27e4:2392:1c92%6
REM    IPv4 Address. . . . . . . . . . . : 192.168.0.26
REM    Subnet Mask . . . . . . . . . . . : 255.255.255.0
REM    Default Gateway . . . . . . . . . : 192.168.0.1
REM
REM Server address:169.254.74.251
REM Opening DESKTOP-NI99V8E:8000
REM
REM With the default parameters, Win10 can connect to Win7 but not the other way around.
REM Win7 sees an IPV6 address when pinging DESKTOP-NI99V8E.
REM the other way around.
REM Netbios names can be used.

REM Other tests:
REM When started from Win10 192.168.0.26, the machine can be found from Win7,
REM but not from Win10 itself.
python survol\scripts\cgiserver.py -b webbrowser -a 192.168.0.26

REM Here the machine is found from Win10 itself.
python survol\scripts\cgiserver.py -b webbrowser -a 127.0.0.1
