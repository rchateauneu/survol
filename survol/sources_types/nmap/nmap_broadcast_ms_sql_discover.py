#!/usr/bin/env python

"""
Nmap MS-SQL discovery

Discovers Microsoft SQL servers in the same broadcast domain.
"""

import re
import sys
import socket
import logging
import xml.dom.minidom

import lib_uris
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

# If pyodbc is available, it adds a link to the databases.
try:
    import pyodbc
    from sources_types.odbc import dsn as survol_odbc_dsn
except ImportError:
    pyodbc = None


# https://nmap.org/nsedoc/scripts/broadcast-ms-sql-discover.html
#
# Starting Nmap 7.12 ( https://nmap.org ) at 2017-11-30 07:45 GMT
# Pre-scan script results:
# | broadcast-ms-sql-discover:
# |   192.168.0.14 (MYMACHINE)
# |     [192.168.0.14\SQLEXPRESS]
# |       Name: SQLEXPRESS
# |       Product: Microsoft SQL Server 2012
# |       TCP port: 1433
# |_      Named pipe: \\192.168.0.14\pipe\MSSQL$SQLEXPRESS\sql\query
# logging.warning: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 5.76 seconds
#
def AddOdbcNode(grph, mach_nam, srv_name, tcp_port):
    # cn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;UID=essaisql;PWD=xyz')
    if lib_util.isPlatformLinux:
        driver_name = "ODBC Driver 13 for SQL Server"
    else:
        driver_name = "ODBC Driver 13 for SQL Server"

    # For example "MYMACHINE\\SQLEXPRESS"
    cred_key = "%s\\%s" % (mach_nam, srv_name)
    logging.debug("cred_key=%s", cred_key)
    a_cred = lib_credentials.GetCredentials("SqlExpress", cred_key)

    if a_cred:
        str_dsn = 'DRIVER={%s};SERVER=%s;PORT=%s;UID=%s;PWD=%s' % (driver_name, mach_nam, tcp_port, a_cred[0], a_cred[1])
        logging.debug("str_dsn=%s", str_dsn)

        node_dsn = survol_odbc_dsn.MakeUri(str_dsn)
        grph.add((lib_common.nodeMachine, pc.property_odbc_dsn, node_dsn))


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    args = ["nmap", '-oX', '-', '--script', "broadcast-ms-sql-discover", ]

    # The returned IP address is wrong when launched from a Windows machine where the DB is running.
    p = lib_common.SubProcPOpen(args)

    grph = cgiEnv.GetGraph()

    nmap_last_output, nmap_err = p.communicate()

    dom = xml.dom.minidom.parseString(nmap_last_output)

    # <script id="broadcast-ms-sql-discover" output="&#xa; 192.168.0.14 (RCHATEAU-HP)&#xa; [192.168.0.14\SQLEXPRESS]&#xa; Name: SQLEXPRESS&#xa; Product: Microsoft SQL Server 2012&#xa; TCP port: 1433&#xa; Named pipe: \\192.168.0.14\pipe\MSSQL$SQLEXPRESS\sql\query&#xa;"/>
    for a_script in dom.getElementsByTagName('script'):
        an_output = a_script.getAttributeNode('output').value.strip()
        logging.debug("an_output=%s", str(an_output))
        arr_split = [a_wrd.strip() for a_wrd in an_output.split("\n")]

        logging.debug("arr_split=%s", str(arr_split))

        # "192.168.0.14 (MYMACHINE)"
        the_mach_full = arr_split[0].strip()
        re_mach = re.match(r"([^ ]*) *\(([^)]*)\)", the_mach_full)
        if re_mach:
            mach_ip = re_mach.group(1)
            mach_nam = re_mach.group(2)

            node_host = lib_uris.gUriGen.HostnameUri(mach_nam)
            grph.add((node_host, lib_common.MakeProp("IP address"), lib_util.NodeLiteral(mach_ip)))
        else:
            node_host = lib_uris.gUriGen.HostnameUri(the_mach_full)
            mach_ip = None
            mach_nam = the_mach_full

        the_name_db = arr_split[1].strip()
        grph.add((node_host, lib_common.MakeProp("Sql server instance"), lib_util.NodeLiteral(the_name_db)))

        tcp_port = None
        srv_name = None

        # MYMACHINE    IP_address    192.168.0.14
        # Name    SQLEXPRESS
        # Named_pipe    \\192.168.0.14\pipe\MSSQL$SQLEXPRESS\sql\query
        # Product    Microsoft SQL Server 2012
        # Sql_server_instance    [192.168.0.14\SQLEXPRESS]
        # TCP_port    1433
        for one_wrd in arr_split[2:]:
            logging.debug("one_wrd=%s", one_wrd)
            one_split = [a_split.strip() for a_split in one_wrd.split(":")]
            one_key = one_split[0]

            if len(one_split) > 1:
                one_val = ":".join(one_split[1:])
                # In case there would be more than one ":"
                grph.add((node_host, lib_common.MakeProp(one_key), lib_util.NodeLiteral(one_val)))
                if one_key == "TCP port":
                    tcp_port = one_val
                elif one_key == "Name":
                    srv_name = one_val
                else:
                    pass
            else:
                grph.add((node_host, pc.property_information, lib_util.NodeLiteral(one_key)))

        if tcp_port and srv_name and pyodbc:
            AddOdbcNode(grph, mach_nam, srv_name, tcp_port)
            AddOdbcNode(grph, mach_ip, srv_name, tcp_port)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
