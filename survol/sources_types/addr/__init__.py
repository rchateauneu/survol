"""
IP socket address
"""

import sys
import socket
import threading
import time
import socket
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def EntityOntology():
    return (["Id"],)


# TODO: Add the network card.


# This returns a nice name given the parameter of the object.
def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]
    host_name, dummy, port_num = entity_id.rpartition(":")

    try:
        port_nam = socket.getservbyport(int(port_num))
    except:
        port_nam = str(port_num)

    return "%s:%s" % (host_name,port_nam)


def AddInfo(grph,node, entity_ids_arr):
    time_start = time.time()
    socket_nam = entity_ids_arr[0]
    socket_split = SplitAddrPort(socket_nam)
    socket_addr = socket_split[0]
    sock_ip = lib_util.GlobalGetHostByName(socket_addr)
    time_end = time.time()
    time_delta = time_end - time_start
    logging.debug("addr.AddInfo tm=%f sock_ip=%s", time_delta, sock_ip)

    node_host = lib_uris.gUriGen.HostnameUri(sock_ip)
    # Should be the otherway round, but it makes the graph ugly.
    grph.add((node, pc.property_has_socket, node_host))


def UniversalAlias(entity_ids_arr, entity_host, entity_class):
    # If IPV4, "host:port". Could be IPv6
    socket_addr, socket_port = SplitAddrPort(entity_ids_arr[0])

    # Is the host an IP address ?
    try:
        socket.inet_aton(socket_addr)
        sock_ip = socket_addr
    except socket.error:
        # This is not an IP address, therefore must be converted.
        sock_ip = lib_util.GlobalGetHostByName(socket_addr)

    if sock_ip == "127.0.0.1":
        sock_ip = lib_util.GlobalGetHostByName(socket.getfqdn())

    # Just in case this would be a service name, turn into a protocol number.
    # It should not happen because lib_uris. AddrUri displays the port as an integer.
    try:
        socket_port_number = socket.getservbyname(socket_port)
    except:
        socket_port_number = socket_port

    uni_alias = str(sock_ip) + ":" + str(socket_port_number)
    return uni_alias


# Add the real url corresponding to this socket so we can nicely click on it.
# This is a bit expeimental.
def DecorateSocketNode(grph, socket_node, host, port, proto):
    socket_node = lib_uris.gUriGen.AddrUri(host, port, proto)

    nod_url = None

    if port == 80 and proto == "tcp":
        str_url = "http://%s" % host
        nod_url = lib_common.NodeUrl(str_url)
        grph.add((nod_url, pc.property_information, lib_util.NodeLiteral("HTTP url")))

    if nod_url:
        grph.add((socket_node, lib_common.MakeProp("port"), nod_url))


################################################################################


def JoinThreads(threads):
    logging.debug("JoinThreads: %d threads to return.", len(threads))
    for thread in threads:
        thread.join()


# This returns retrieves the host information corresponding to a network address.
# It might take a long time due to DNS delay, therefore one thread is started per host.
def GetHost(addr):
    try:
        return socket.gethostbyaddr(addr)
    except socket.herror:
        return [addr, []]


# Different interfaces according to the psutil version.
def SocketToPair(connect):
    try:
        larray = connect.laddr
        rarray = connect.raddr
    except AttributeError:
        # Old psutil versions.
        larray = connect.local_address
        rarray = connect.remote_address
    return larray, rarray


# The input could be '192.168.0.17:22' or '[fe80::3c7a:339:64f0:2161%11]:51769'
# If IPV6, it removes the surrounding square brackets.
def SplitAddrPort(addr):
    idx_col = addr.rfind(":")
    if idx_col < 0:
        return ("", 0)

    if addr[0] == '[':
        the_host = addr[1:idx_col-1]
    else:
        the_host = addr[:idx_col]

    # FIXME: Should be OK: This applies only to IPV6
    the_host = the_host.replace("%", "_")

    the_port = addr[idx_col+1:]
    return the_host, the_port


class PsutilAddSocketThread(threading.Thread):
    """
    This asynchronously adds a RDF relation between a process and a socket.
    As it is asychronous, we can make a DNS query.
    """
    def __init__(self, node_process, connect, grph, grph_lock):
        self.node_process = node_process
        self.connect = connect
        self.grph = grph
        self.grph_lock = grph_lock

        threading.Thread.__init__(self)

    # TODO: We might, in the future, have one single object instead of two.
    # For example "socket_pair".
    def run(self):
        # Now we create a node in rdflib, and we need a mutex for that.
        try:
            self.grph_lock.acquire()
            larray, rarray = SocketToPair(self.connect)

            lhost = GetHost(larray[0])[0]
            lsocket_node = lib_uris.gUriGen.AddrUri(lhost, larray[1])

            try:
                rhost = GetHost(rarray[0])[0]
                rsocket_node = lib_uris.gUriGen.AddrUri(rhost, rarray[1])
                self.grph.add((lsocket_node, pc.property_socket_end, rsocket_node))
            except IndexError:
                pass

            # TODO: Not sure.
            self.grph.add((self.node_process, pc.property_has_socket, lsocket_node))
            self.grph.add((lsocket_node, pc.property_information, lib_util.NodeLiteral(self.connect.status)))
        finally:
            self.grph_lock.release()


def PsutilAddSocketToGraphAsync(node_process, connects, grph, flag_show_unconnected):
    threads_arr = []
    grph_lock = threading.Lock()

    for cnt in connects:
        if( (cnt.family == socket.AF_INET)
        and (cnt.type == socket.SOCK_STREAM)
        and (flag_show_unconnected or (cnt.status == 'ESTABLISHED'))
        ):
            thr = PsutilAddSocketThread(node_process, cnt, grph, grph_lock)
            thr.start()
            threads_arr.append(thr)

    JoinThreads(threads_arr)


# TODO: We might, in the future, have one single object instead of two.
# TODO: Remove this hardcode !!!
# For example "socket_pair". Not sure.
def PsutilAddSocketToGraphOne(node_process, connect, grph):
    if((connect.family == 2) and (connect.type == 1)):
    #and ( connect.status == 'ESTABLISHED' )

        larray, rarray = SocketToPair(connect)
        lsocket_node = lib_uris.gUriGen.AddrUri(larray[0], larray[1])
        try:
            rsocket_node = lib_uris.gUriGen.AddrUri(rarray[0], rarray[1])
        except IndexError:
            rsocket_node = None

        # TODO: Should rather have a commutative link.
        if rsocket_node != None:
            grph.add((lsocket_node, pc.property_socket_end, rsocket_node))

        # How can we be sure that one of the sockets is linked to the host ?
        grph.add((node_process, pc.property_has_socket, lsocket_node))
        grph.add((lsocket_node, pc.property_information, lib_util.NodeLiteral(connect.status)))


def PsutilAddSocketToGraph(node_process, connects, grph):
    for cnt in connects:
        PsutilAddSocketToGraphOne(node_process, cnt, grph)
