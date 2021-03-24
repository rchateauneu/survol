# If the CGI script crashes before finishing the headers, cgitb will emit invalid HTTP headers before showing the error message.
# The workaround is to put: HttpProtocolOptions Unsafe line into the apache .conf


import cgitb

import os

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020-2021, Primhill Computers"
__license__     = "GPL"

# This library is used by CGI scripts and command-line scripts.
# Therefore, its behaviour is different in case of error.
if "PYTEST_CURRENT_TEST" in os.environ:
    # Do this when called in a deamon or pytest. Otherwise it is not readable
    cgitb.enable(format="txt")
elif os.getenv("SERVER_SOFTWARE"):
    cgitb.enable()

import re
import sys
import six
import cgi
import time
import socket
import base64
import importlib
import logging
import inspect
import rdflib
import subprocess

# This minimizes changes because it is used everywhere.
from scripts.naming_conventions import standardized_file_path
from scripts.naming_conventions import standardized_memmap_path

is_py3 = sys.version_info >= (3,)

if is_py3:
    from urllib.parse import quote as urllib_quote
    from urllib.parse import unquote as urllib_unquote
    from urllib.parse import urlparse as survol_urlparse
    from urllib.parse import parse_qs

    import html
    import html.parser
    def survol_unescape(s):
        return html.parser.unescape(s)

    html_escape = html.escape

    from urllib.request import urlopen as survol_urlopen
else:
    from urllib import quote as urllib_quote
    from urllib import unquote as urllib_unquote
    from urlparse import urlparse as survol_urlparse
    from urlparse import parse_qs

    # TODO: html might be present, so it might be worth testing.
    import HTMLParser
    def survol_unescape(s):
        return HTMLParser.HTMLParser().unescape(s)

    html_escape = cgi.escape

    from urllib2 import urlopen as survol_urlopen


################################################################################

def SetLoggingConfig(log_level):
    # Reinit: https://stackoverflow.com/questions/12158048/changing-loggings-basicconfig-which-is-already-set
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # This avoids the message "No handlers could be found for logger "rdflib.term""
    logging.basicConfig(
        stream=sys.stderr,
        format='%(asctime)s %(levelname)8s %(filename)s %(lineno)d %(message)s',
        level = log_level)


SetLoggingConfig(logging.WARNING)

# Avoid this message:
# 2018-09-18 21:57:54,868  WARNING rdflib.term term.py 207: http://L... does not look like a valid URI, trying to serialize this will break.
loggerRdflib = logging.getLogger("rdflib.term")
loggerRdflib.setLevel(logging.WARNING)

# This is the general purpose logger.
logger_name = "survol_logger"

gblLogger = logging.getLogger(logger_name)

################################################################################

# Returns None even if jinja2 is available but configuration does not use it.
def GetJinja2():
    try:
        import jinja2
        return jinja2
    except:
        return None

################################################################################

# Sometimes we have to display many strings of the same type, for example
# filenames or WMI monikers. These strings are mixes of words and numbers.
# They do not sort naturally well, because the numbers are lexicographically
# sorted. The Python module natsort does that.
# Simple yet flexible natural sorting in Python.
try:
    import natsort
    from natsort import natsort_keygen

    natural_sorted = natsort.natsorted

    def natural_sort_list(one_list, **args):

        natsort_key = natsort_keygen()

        try:
            orig_key = args['key']
            args['key'] = lambda in_param: natsort_key(orig_key(in_param))
        except KeyError:
            args['key'] = natsort_key
        one_list.sort(**args)
except ImportError:
    logging.warning("WritePatterned Module natsorted not available.")
    natural_sorted = sorted

    def natural_sort_list(one_list, **args):
        one_list.sort(**args)

################################################################################

# This avoids needing the "six" module which is not always available.
# On some environments, it is a hassle to import it.
if is_py3:
    def six_iteritems(array):
            return array.items()
else:
    def six_iteritems(array):
        return array.iteritems()

# Add all usual Python types.
scalar_data_types = six.string_types + (six.text_type, six.binary_type, float, bool) + six.integer_types

################################################################################

NodeLiteral = rdflib.Literal

NodeUrl = rdflib.term.URIRef

################################################################################


def AddSIUnit(number, unitSI):
    """
    unitSI = "B", "b", "B/s" for example.
    This is different from an integer ID which should always be displayed "as is", just like a string.
    We might have units such as "B/B" which are without dimensions.
    """

    # TODO: We need a way to describe a number of items, without unit.
    if unitSI:
        return str(number) + " " + unitSI
    else:
        return str(number)

################################################################################


def HttpPrefix():
    """This is the protocol, the server address followed by the port:
     "http://192.168.0.14:80", "http://mymachine:8000" """

    # Default values for ease of testing, so CGI scripts can be run as is from command line..
    try:
        server_addr = os.environ['SERVER_NAME']
        # This is a special value if the client library is in local mode.
        if server_addr != "LOCALHOST":
            # Hostnames always in lowercase.
            server_addr = server_addr.lower()

        # 'REMOTE_ADDR'] => "127.0.0.1"
        # 'SERVER_NAME'] => "mymachine"
        # 'REMOTE_HOST'] => "mymachine"

    except KeyError:
        logging.error("HttpPrefix SERVER_NAME MUST BE DEFINED")
        sys.exit(1)
    
    try:
        server_port = os.environ['SERVER_PORT']
    except KeyError:
        # Default HTTP port.
        server_port = "80"

    # BEWARE: Colons are forbidden in URIs apparently !!!
    # Due to a very strange bug which displays:
    # "http://127.0.0.1:80/PythonStyle/survol/entity.py" ...
    # does not look like a valid URI, trying to serialize this will break.
    # But if we do not add "http:" etc... SVG adds its prefix "127.0.0.1" etc...
    prfx = 'http://' + server_addr + ':' + server_port
    # sys.stderr.write("HttpPrefix server_addr=%s prfx=%s\n"%(server_addr,prfx))
    return prfx


# This is also used in lib_client to differentiate local from remote scripts.
# Objects need an URL, but if no agent is used, we need a pseudo-URL,
# represented by the string, by convention. Syntactically, this is a correct URL.
prefixLocalExecution = "/LocalExecution"


def UriRootHelper():
    try:
        # Checks of this environment variable is defined.
        os.environ["SERVER_NAME"]
    except KeyError:
        # This is necessary when returning objects for example from get_instances()
        # in the client library lib_client.py. The local objects need a hostname,
        # and "localhost" fills this role.
        # However, if used with remote objects, this hostname should be replaced
        # on-the-fly by the actual host name.
        # An alternative is to specify the right hostname here.
        os.environ["SERVER_NAME"] = socket.gethostname().lower()
    try:
        # SCRIPT_NAME=/PythonStyle/survol/internals/print.py
        # SCRIPT_NAME=/survol/print_environment_variables.py
        scriptNam=os.environ['SCRIPT_NAME']
        idx = scriptNam.find('survol')
        if idx >= 0:
            root = scriptNam[:idx] + 'survol'
        else:
            # Should not happen.
            root = "/NON_SURVOL_URL/" + scriptNam

    except KeyError:
        # If this runs from the command line and not as a CGI script,
        # then this environment variable is not set.
        # Just like SERVER_NAME, it should test that the caller is lib_client.py.
        root = prefixLocalExecution
    urh = HttpPrefix() + root
    return urh


uriRoot = UriRootHelper()


################################################################################

# This returns the hostname as a string. Some special processing because on Windows,
# the returned hostname seems truncated.
# See lib_uris.HostnameUri()
#
# socket.gethostname()                 socket.gethostbyaddr(socket.gethostname()) 
# fedora22                             ('advancedsearch.virginmedia.com', [], ['81.200.64.50'])
# mymachine                          ('mymachine', [], ['fe80::3c7a:339:64f0:2161'])
# ssh02.cluster023.gra.hosting.ovh.net ('ssh02.cluster023.gra.hosting.ovh.net', ['ssh02'], ['10.23.90.2'])
#
# Some example of the values of important CGI variables:
# mymachine IP address is 192.168.0.14
#
# http://mymachine:8000/survol/print_environment_variables.py
# SERVER_SOFTWARE=SimpleHTTP/0.6 Python/2.7.10
# SERVER_NAME=mymachine
#
# http://mymachine/Survol/survol/print_environment_variables.py
# SERVER_SOFTWARE=Apache/2.4.12 (Win64) OpenSSL/1.0.1m mod_wsgi/4.4.12 Python/2.7.10
# SERVER_NAME=mymachine
# SERVER_ADDR=fe80::3c7a:339:64f0:2161
# HTTP_HOST=mymachine
#
# http://127.0.0.1/Survol/survol/print_environment_variables.py
# SERVER_SOFTWARE=Apache/2.4.12 (Win64) OpenSSL/1.0.1m mod_wsgi/4.4.12 Python/2.7.10
# SERVER_NAME=127.0.0.1
# SERVER_ADDR=127.0.0.1
# HTTP_HOST=127.0.0.1
#
# http://192.168.0.14/Survol/survol/print_environment_variables.py
# SERVER_SOFTWARE=Apache/2.4.12 (Win64) OpenSSL/1.0.1m mod_wsgi/4.4.12 Python/2.7.10
# SERVER_NAME=192.168.0.14
# SERVER_ADDR=192.168.0.14
# HTTP_HOST=192.168.0.14
#
# This is 192.168.0.17 accessible via NAT and primhillcomputers.ddns.net:
#
# http://primhillcomputers.ddns.net/Survol/survol/print_environment_variables.py
# SERVER_SOFTWARE=Apache/2.4.18 (Fedora) PHP/5.6.23 mod_wsgi/4.4.8 Python/2.7.10
# SERVER_NAME=primhillcomputers.ddns.net
# SERVER_ADDR=192.168.0.17
# HTTP_HOST=primhillcomputers.ddns.net
#
# http://192.168.0.17/Survol/survol/print_environment_variables.py
# SERVER_SOFTWARE=Apache/2.4.18 (Fedora) PHP/5.6.23 mod_wsgi/4.4.8 Python/2.7.10
# SERVER_NAME=192.168.0.17
# SERVER_ADDR=192.168.0.17
# HTTP_HOST=192.168.0.17
#
# Todays, my IP address is 82.45.12.63, so let's try to access the same machine:
# http://82.45.12.63/Survol/survol/print_environment_variables.py
# SERVER_SOFTWARE=Apache/2.4.18 (Fedora) PHP/5.6.23 mod_wsgi/4.4.8 Python/2.7.10
# SERVER_NAME=82.45.12.63
# SERVER_ADDR=192.168.0.17
# HTTP_HOST=82.45.12.63
#
# It is better to rely on a distributed naming system: DNS or plain IP address.
def HostName():
    # SERVER_NAME is set by the HTTP server and might be wrong, but gives some consistency.

    # Converted to lowercase because of RFC4343: Domain Name System (DNS) Case Insensitivity Clarification
    return os.environ["SERVER_NAME"].lower()


currentHostname = HostName()


def GlobalGetHostByName(host_nam):
    try:
        the_ip = socket.gethostbyname(host_nam)
        return the_ip
    except Exception:
        return host_nam


# Beware: The machine might have several IP addresses.
try:
    # BEWARE: Possibly very slow.
    localIP = GlobalGetHostByName(currentHostname)
except Exception:
    # Apparently, it happens if the router is down.
    localIP = "127.0.0.1"


def is_local_address(an_host_nam):
    """
    This is for example used by WMI, which does not accept credentials
    for a local machine: We must therefore be sure that the machine is local or not.
    """

    # Maybe entity_host="http://192.168.1.83:5988"
    host_only = EntHostToIp(an_host_nam)
    if host_only in [None, "", "localhost", "127.0.0.1", currentHostname]:
        return True

    try:
        ip_only = GlobalGetHostByName(host_only)
    # socket.gaierror
    except Exception as exc:
        # Unknown machine
        return False

    # is_local_address MYHOST-HP ip_only=192.168.0.14 localIP=127.0.0.1 currentHostname=127.0.0.1
    if ip_only in ["0.0.0.0", "127.0.0.1", localIP]:
        return True

    # "MYHOST-HP" and "myhost-HP" ??
    if an_host_nam.lower() == socket.gethostname().lower():
        return True

    return False


# Beware: lib_util.currentHostname="Unknown-30-b5-c2-02-0c-b5-2.home"
# socket.gethostname() = 'Unknown-30-b5-c2-02-0c-b5-2.home'
# socket.gethostbyaddr(hst) = ('Unknown-30-b5-c2-02-0c-b5-2.home', [], ['192.168.1.88'])
def same_host_or_local(srv, ent_host):
    if (ent_host == srv) or ((ent_host is None or ent_host in ["", "0.0.0.0"]) and (localIP == srv)):
        # We might add credentials.
        return True
    else:
        return False

################################################################################


def TopUrl(entity_type, entity_id):
    """ This returns the top-level URL"""
    try:
        script_nam = os.environ['SCRIPT_NAME']
    except KeyError:
        script_nam = "Hello.py"
    if re.match( ".*/survol/entity.py.*", script_nam):
        if entity_type == "":
            top_url = uriRoot + "/entity.py"
        else:
            # Same as in objtypes.py
            if entity_id == "" or re.match("[a-zA-Z_]*=", entity_id):
                top_url = uriRoot + "/entity.py"
            else:
                top_url = EntityUri(entity_type, "")
    else:
        top_url = uriRoot + "/entity.py"
    return top_url

################################################################################


def EncodeUri(an_str):
    # This, because graphviz transforms a "\\L" (backslash-L) into "<TABLE>". Example:
    # http://127.0.0.1/PythonStyle/survol/entity.py?xid=com_type_lib:C%3A%5CWINDOWS%5Csystem32%5CLangWrbk.dll
    # Or if the url contains a file in "App\\Local"
    strTABLE = an_str.replace("\\L", "\\\\L")

    # In Python 3, urllib.quote is renamed urllib.parse.quote and handles unicode by default.
    if is_py3:
        return urllib_quote(strTABLE, '')
    else:
        # THIS SHOULD NORMALLY BE DONE. BUT WHAT ??
        ###strTABLE = strTABLE.replace("&","%26")
        # UnicodeDecodeError: 'ascii' codec can't decode byte 0xe9 in position 32
        return urllib_quote(strTABLE, 'ascii')

################################################################################


def RequestUri():
    """This function returns the value of the environment variable REQUEST_URI.
    But, a minimal HTTP server such as CGIHTTPServer does not set REQUEST_URI.
    So its value is recreated with available values in other environment variables.
    """
    try:
        # Example: REQUEST_URI=/Survol/survol/print_environment_variables.py
        script = os.environ["REQUEST_URI"]
        #sys.stderr.write("RequestUri script=%s\n"%script)
    except KeyError:
        try:
            # For example SCRIPT_NAME=/survol/print_environment_variables.py
            script = os.environ['SCRIPT_NAME']

            # Normalizes "survol\sources_types/a_script.py" into "/survol/sources_types/a_script.py"
            # This is for the case of debugging a script from the command line: If the URL is also an event key,
            # it must be the same as the one set by the HTTP server.
            if not script.startswith("/"):
                script = "/" + script
            script = script.replace("\\", "/")

            try:
                # For example QUERY_STRING="xid=EURO%5CLONL00111310@process:16580"
                query_string = os.environ['QUERY_STRING']
                if query_string:
                    script += "?" + query_string
            except KeyError:
                script = "QUERY_STRING should be set in RequestUri()"
        except KeyError:
            script = "SCRIPT_NAME should be set in RequestUri()"
    return script

################################################################################


# This assumes that this file is at the top of "survol" package.

# This fails with Cython due to a bug in Python 2,
# with <type 'exceptions.NameError'>: name '__file__' is not defined
# https://stackoverflow.com/questions/19630634/python-file-is-not-defined

# In Python modules, the top-level module code sees the __file__ variable
# and can use it to refer to resources in package subdirectories, for example.
# This is not currently possible in extension modules,
# because __file__ is only set after running the module init function,
# and the module has no way to find out its runtime location.
#
# CPython should set __file__ directly in PyModule_Create2(),
# based on information provided by the shared library loader.
# This would let PyModule_GetFilenameObject() work immediately with the newly created module object.

gblTopScripts = os.path.dirname(os.path.abspath(__file__))
sys.path.append(gblTopScripts)


def EntHostToIp(entity_host):
    """Depending on the category, entity_host can have several forms.
    The name is misleading because it returns a host name,
    which might or might not be an IP."""

    if entity_host is None:
        return None

    # WBEM: http://192.168.1.88:5988
    #       https://jdd:test@acme.com:5959
    #       http://192.168.1.88:5988
    # TODO: Not sure this will work with IPV6
    mtch_host_wbem = re.match("https?://([^/:]*).*", entity_host)
    if mtch_host_wbem:
        return mtch_host_wbem.group(1)

    # WMI : \\MYHOST-HP
    mtch_host_wmi = re.match(r"\\\\([-0-9A-Za-z_\.]*)", entity_host)
    if mtch_host_wmi:
        return mtch_host_wmi.group(1)

    return entity_host


# TODO: Coalesce with EntHostToIp
def EntHostToIpReally(entity_host):
    try:
        hostOnly = EntHostToIp(entity_host)
        return GlobalGetHostByName(hostOnly) # POSSIBLY VERY SLOW.
    except Exception:
        return hostOnly

################################################################################


def _parse_xid_local(xid):
    """
    A machine name can contain a domain name : "WORKGROUP\\MYHOST-HP", the backslash cannot be at the beginning.
    "WORKGROUP\\MYHOST-HP@CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2"
    "WORKGROUP\\MYHOST-HP@oracle/table.Name=MY_TABLE"
    BEWARE: This must NOT match "http://127.0.0.1:8000/survol/namespaces_wbem.py?xid=http://192.168.1.83:5988/."
    that is "http://192.168.1.83:5988/."
    A class name starts with a letter. There are no consecutives slashes "/".
    """

    assert isinstance(xid, str), "Type should not be %s" % str(type(xid))

    # TODO: Filter when consecutives slashes. Pre-compile this regular expression.
    mtch_entity = re.match(r"([-0-9A-Za-z_]*\\?[-0-9A-Za-z_\.]*@)?([a-zA-Z_][a-z0-9A-Z_/]*)\.(.*)", xid)

    if mtch_entity:
        if mtch_entity.group(1) == None:
            entity_host = ""
        else:
            entity_host = mtch_entity.group(1)[:-1]

        entity_type = mtch_entity.group(2)
        entity_id_quoted = mtch_entity.group(3)

        # Everything which comes after the dot which follows the class name.
        entity_id = urllib_unquote(entity_id_quoted)

        return entity_type, entity_id, entity_host

    return None


def _parse_xid_wmi(xid):
    # WMI : \\MYHOST-HP\root\cimv2:Win32_Process.Handle="0"
    # Beware ! On Windows, namespaces are separated by backslashes.
    # WMI : \\MYHOST-HP\root\cimv2:Win32_Process.Handle="0"
    # http://127.0.0.1:8000/survol/objtypes_wmi.py?xid=\\myhost-HP\root\CIMV2\Applications%3A.
    # http://127.0.0.1:8000/survol/class_wmi.py?xid=\\myhost-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.
    # http://127.0.0.1:8000/survol/entity_wmi.py?xid=\\MYHOST-HP\root\CIMV2%3AWin32_PerfFormattedData_Counters_IPHTTPSGlobal.Name%3D%22Default%22
    # TODO: BEWARE ! If the host name starts with a L, we have to "triplicate" the back-slash
    # TODO: otherwise graphviz replace "\L" par "<TABLE">

    # This matches for example 'root\cimv2:Win32_Process.Handle="0"'
    wmi_regex_local_part = r"([a-zA-Z0-9_]+)\\([^.]*)(\..*)"

    mtch_ent_wmi = re.match(r"\\\\\\?([-0-9A-Za-z_\.]*)\\" + wmi_regex_local_part, xid)
    if mtch_ent_wmi:
        grp = mtch_ent_wmi.groups()
        entity_host = grp[0]
        entity_type = grp[1] + "\\" + grp[2]
        entity_id_quoted = grp[3]
        # ( entity_host, entity_type, entity_id_quoted ) = grp
        if entity_id_quoted is None:
            entity_id = ""
            # sys.stderr.write("WMI Class Cimom=%s ns_type=%s\n" % ( entity_host, entity_type ))
        else:
            # Remove the dot which comes after the class name.
            entity_id = urllib_unquote(entity_id_quoted)[1:]
            # sys.stderr.write("WMI Object Cimom=%s ns_type=%s path=%s\n" % ( entity_host, entity_type, entity_id ))

        return entity_type, entity_id, entity_host

    # WMI : Maybe the host is missing, and implicitely the local machine.
    # http://127.0.0.1:8000/survol/class_type_all.py?xid=root\CIMV2:Win32_Process.
    mtch_ent_wmi = re.match(wmi_regex_local_part, xid)
    if mtch_ent_wmi:
        grp = mtch_ent_wmi.groups()
        entity_host = ""
        entity_type = grp[0] + "\\" + grp[1]
        entity_id_quoted = grp[2]
        if entity_id_quoted is None:
            entity_id = ""
            # sys.stderr.write("WMI Class Cimom=%s ns_type=%s\n" % ( entity_host, entity_type ))
        else:
            # Remove the dot which comes after the class name.
            entity_id = urllib_unquote(entity_id_quoted)[1:]
            # sys.stderr.write("WMI Object Cimom=%s ns_type=%s path=%s\n" % ( entity_host, entity_type, entity_id ))

        return entity_type, entity_id, entity_host

    return None


def _parse_xid_wbem(xid):
    # https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"
    # http://192.168.1.88:5988/root/PG_Internal:PG_WBEMSLPTemplate
    # "http://127.0.0.1:8000/survol/namespaces_wbem.py?xid=http://192.168.1.83:5988/."
    # "xid=http://192.168.1.88:5988/."
    mtch_ent_wbem = re.match(r"(https?://[^/]*)/([^.]*)(\..*)?", xid)
    if mtch_ent_wbem:
        #sys.stderr.write("mtch_ent_wbem\n")
        grp = mtch_ent_wbem.groups()
        (entity_host, entity_type, entity_id_quoted) = grp
        # TODO: SAME LOGIC FOR THE TWO OTHER CASES !!!!!!!!!!!!!!
        if entity_id_quoted is None:
            entity_id = ""
            # sys.stderr.write("WBEM Class Cimom=%s ns_type=%s\n" % ( entity_host, entity_type ))
        else:
            # Remove the dot which comes after the class name.
            entity_id = urllib_unquote(entity_id_quoted)[1:]
            # sys.stderr.write("WBEM Object Cimom=%s ns_type=%s path=%s\n" % ( entity_host, entity_type, entity_id ))

        return entity_type, entity_id, entity_host

    return None


def ParseXid(xid):
    """
    This receives the xid value for, for example: "xid=@/:oracle_package."
    It parses this string into three components and returns the class,
    the concatenation of key=value pairs, and the host.
    BEWARE: This cannot work if the hostname contains a ":", see IPV6. MUST BE VERY FAST !!!
    TODO: Should also parse the namespace.
    ParseXid xid=CIM_ComputerSystem.Name=mymachine
    ParseXid xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2
    """

    # First, we try to match our terminology.
    # The type can be in several directories separated by slashes: "oracle/table"
    # If suffixed with "/", it means namespaces.
    assert isinstance(xid, str), "Type should not be %s" % str(type(xid))
    entity_triplet = _parse_xid_local(xid)
    if entity_triplet:
        return entity_triplet

    # Apparently it is not a problem for the plain old entities.
    xid = urllib_unquote(xid)

    entity_triplet = _parse_xid_wmi(xid)
    if entity_triplet:
        return entity_triplet

    entity_triplet = _parse_xid_wbem(xid)
    if entity_triplet:
        return entity_triplet

    return "", "", ""

################################################################################


# TODO: Would probably be faster by searching for the last "/".
# '\\\\MYHOST-HP\\root\\cimv2:Win32_Process.Handle="0"'  => "root\\cimv2:Win32_Process"
# https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"  => ""
def parse_namespace_type(ns_entity_type):
    ns_split = ns_entity_type.split(":")
    if len(ns_split) == 1:
        entity_namespace = ""
        entity_type = ns_split[0]
    else:
        entity_namespace = ns_split[0]
        entity_type = ns_split[1]
    return entity_namespace, entity_type

################################################################################


# TODO: Consider base64 encoding of all arguments, with "Xid="
# This would give the same encoding for all parameters whetever their class.
xidCgiDelimiter = "?xid="


def _encode_entity_id(entity_type, entity_id):
    """See xidCgiDelimiter = "?xid=" """
    return "xid=%s.%s" % (entity_type, entity_id)


def ScriptizeCimom(path, entity_type, cimom):
    """This is a adhoc solution, for a local use."""
    return uriRoot + path + "?" + _encode_entity_id(cimom + "/" + entity_type, "")


def Scriptize(path, entity_type, entity_id):
    """Properly encodes type and id into a URL."""
    return uriRoot + path + "?" + _encode_entity_id(entity_type, entity_id)

################################################################################


def BuildWmiMoniker(hostname_wmi, namespac="", class_nam=""):
    if hostname_wmi:
        return "\\\\%s\\%s:%s." % (hostname_wmi, namespac, class_nam)
    else:
        if namespac:
            return "\\\\%s\\%s:%s." % (namespac, class_nam)
        else:
            return "%s." % class_nam


def EntityClassUrl(entity_type, entity_namespace="", entity_host="", category=""):
    """This creates the URL of a class, "Survol, "WMI" or "WBEM"."""
    if entity_type is None:
        entity_type = ""

    # WBEM: https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"
    if category == "WBEM":
        moniker_class = entity_host + "/" + entity_namespace + ":" + entity_type + "."
    # WMI : \\MYHOST-HP\root\cimv2:Win32_Process.Handle="0"
    elif category == "WMI":
        return BuildWmiMoniker(entity_host, entity_namespace, entity_type)
    # This is temporary.
    else:
        # We could simplify the format, if no namespace nor hostname.
        moniker_class = ""
        if entity_host:
            moniker_class += entity_host + "@"
        # Should not happen.
        if entity_namespace:
            moniker_class += entity_namespace + "/:"
        moniker_class += entity_type + "."

    # TODO: See also EntityUrlFromMoniker.

    url = uriRoot + "/class_type_all.py" + xidCgiDelimiter + EncodeUri(moniker_class)
    return url


def EntityClassNode(entity_type, entity_namespace="", entity_host="", category=""):
    """This creates the node of a class, "Survol" (Default), "WMI" or "WBEM"."""
    url = EntityClassUrl(entity_type, entity_namespace, entity_host, category)

    # sys.stdout.write("EntityClassUrl url=%s\n" % url)
    return NodeUrl(url)


def KWArgsToEntityId(class_name, **kwargs_ontology):
    """From key-value pairs, this builds an entity_id in the good property order."""
    entity_id = ""
    delim = ""
    keys_onto = OntologyClassKeys(class_name)

    # The dictionary is not properly ordered because it depends
    # on the Python version, and these data are given by a user application.

    for arg_key in keys_onto:
        try:
            arg_val = kwargs_ontology[arg_key]
        except KeyError:
            logging.error("KWArgsToEntityId className=%s. No key %s", class_name, arg_key)
            raise

        # TODO: The values should be encoded when needed, probably with B64 !!!
        entity_id += delim + "%s=%s" % (arg_key, arg_val)
        delim = ","
    # The values might come from many different origins
    if not is_py3:
        if type(entity_id) == unicode:
            entity_id = entity_id.encode("utf-8")
    return entity_id


def EntityUri(entity_type, *entity_ids):
    """
    This receives a class name and values of attributes, and returns the url of the associated object.
    This url is unique.

    :param entity_type: The class name of the object.
    :param entity_ids: The values of the attributes of the object, in the order of the ontology.
    :return:
    """
    keys = OntologyClassKeys(entity_type)

    if len(keys) != len(entity_ids):
        logging.warning("EntityUri entity_type=%s Different lens:%s and %s", entity_type, str(keys), str(entity_ids))

    # TODO: Base64 encoding is needed in the general case.
    entity_id = ",".join("%s=%s" % pair_kw for pair_kw in zip(keys, entity_ids))
    
    url = Scriptize("/entity.py", entity_type, entity_id)
    return NodeUrl(url)


def EntityUriFromMoniker(entity_type, entity_id):
    """
    This helper function is needed because the key-value pairs defining an object
    are stored in different ways, depending on the context:
    * As a moniker, like on a URL.
    * As a list of values, ordered by the ontology (list of attributes).
    * As a dict of key-value pairs.

    :param entity_type: The class of the object
    :param entity_id: The key-value pairs concatenated into a single moniker string.
    :return: The URL of the object.
    """

    # TODO: Some simplification could be done:
    # TODO: * Use a moniker only when close to an URL.
    # TODO: * Replace list of values by list of key-value pairs.
    # TODO: * Use a dict of key-value pairs only when a lookup is needed.

    entity_ids_arr = EntityIdToArray(entity_type, entity_id)
    entity_url = EntityUri(entity_type, *entity_ids_arr)
    return entity_url


################################################################################


def EntityScriptFromPath(moniker_entity, is_class, is_namespace, is_hostname):
    """Probably not necessary because we apparently always know
    if we need a WMI, WBEM or custom scripts. Not urgent to change this."""
    if moniker_entity[0] == '\\':
        ent_idx = 0
    elif moniker_entity[0:4] == 'http':
        ent_idx = 1
    else:
        ent_idx = 2

    if is_hostname:
        return ('namespaces_wmi.py', 'namespaces_wbem.py', 'entity.py')[ent_idx]
    elif is_namespace:
        return ('objtypes_wmi.py', 'objtypes_wbem.py', 'objtypes.py')[ent_idx]
    elif is_class:
        return ('class_wmi.py', 'class_wbem.py', 'class_type_all.py')[ent_idx]
    else:
        return ('entity_wmi.py', 'entity_wbem.py', 'entity.py')[ent_idx]


# WMI, WBEM and Survol have the similar monikers.
# TODO: This should split the arguments and reformat them according to the class.
# TODO: This, because some parameters must be reformatted,
# TODO: for example CIM_ComputerSystem.Name must be in lowercase.
# TODO: The problem can be fixed by converting all hostnames to uppercase,
# TODO: but we must be sure that WBEM and WMI will follow the same standard.
# TODO: Probably same problem with CIM_DataFile on Windows because of backslashes
# TODO: as directory separator.
def EntityUrlFromMoniker(moniker_entity, is_class=False, is_namespace=False, is_hostname=False):
    script_path = EntityScriptFromPath(moniker_entity, is_class, is_namespace, is_hostname)

    url = uriRoot + "/" + script_path + xidCgiDelimiter + EncodeUri(moniker_entity)
    return url

################################################################################


def ComposeTypes(*hierarchical_entity_types):
    """Used to define subtypes."""
    # TODO: Find another solution more compatible with WBEM and WMI logic.
    return ".".join(hierarchical_entity_types)

################################################################################


def CopyFile(mime_type, file_name):
    """
    This copies the content of a file to standard output.
    It is used to display files as MIME content.

    Read and write by chunks, so that it does not use all memory."""
    logging.debug("CopyFile type globalOutMach=%s" % type(globalOutMach))

    fil_des = open(file_name, "rb")

    globalOutMach.HeaderWriter(mime_type)

    out_fd = globalOutMach.OutStream()

    # https://stackoverflow.com/questions/2374427/python-2-x-write-binary-output-to-stdout
    if is_apache_server():
        if isPlatformWindows:
            if not is_py3:
                import os, msvcrt
                msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    # This is a bit tricky for WSGI if an error occurs:
    # The header must always be sent before the content, and once only.
    # os.environ["SERVER_SOFTWARE"] = "WSGIServer/0.2"
    while True:
        chunk = fil_des.read(1000000)
        if not chunk:
            break
        #  or os.environ["SERVER_SOFTWARE"].startswith("Apache/")
        if is_wsgi_server():
            try:
                out_fd.write(chunk)
            except:
                # 'ascii' codec can't decode byte 0xf3 in position 1: ordinal not in range(128).
                out_fd.write(u"Cannot display:%s" % file_name)
        else:
            out_fd.write(chunk)

    out_fd.flush()
    fil_des.close()

################################################################################


# TODO: When calling a RDF source, we should check the type of the MIME document,
# TODO: and if this is not RDF, the assumes it's an error which must be displayed.

def InfoMessageHtml(message):
    """This is used as a HTML page but also displayed in Javascript in a DIV block. """

    # TODO: Change this for WSGI.
    globalOutMach.HeaderWriter("text/html")

    WrtAsUtf(
        "<html><head><title>Error: Process=%s</title></head>"
        % str(os.getpid()))

    WrtAsUtf("<body>")

    WrtAsUtf("<b>" + message + "</b><br>")

    WrtAsUtf('<table>')

    if is_py3:
        WrtAsUtf("<tr><td>Login</td><td>%s</td></tr>"%os.getlogin())

    WrtAsUtf("<tr><td>Cwd</td><td>%s</td></tr>" % os.getcwd())
    WrtAsUtf("<tr><td>OS</td><td>%s</td></tr>" % sys.platform)
    WrtAsUtf("<tr><td>Version</td><td>%s</td></tr>" % sys.version)
    
    WrtAsUtf('</table>')

    # http://desktop-ni99v8e:8000/survol/www/configuration.htm
    config_url = uriRoot + "/edit_configuration.py"
    WrtAsUtf('<a href="%s">Setup</a>.<br>' % config_url)
    envs_url = uriRoot + "/print_environment_variables.py"
    WrtAsUtf('<a href="%s">Environment variables</a>.<br>' % envs_url)
    home_url = TopUrl("", "")
    WrtAsUtf('<a href="%s">Return home</a>.<br>' % home_url)

    WrtAsUtf("""
    </body></html>
    """)
    gblLogger.debug("InfoMessageHtml:Leaving")

################################################################################


def _object_types_no_cache():
    """Returns the list of available object types:
    ["CIM_Process", "CIM_DataFile" etc...]"""
    directory = gblTopScripts + "/sources_types"

    ld = len(directory)
    for path, dirs, files in os.walk(directory):
        if len(path) == ld:
            prefix = ""
        else:
            prefix = path[ld +1:].replace("\\", "/") + "/"
        for one_dir in dirs:
            if one_dir != "__pycache__":
                yield prefix + one_dir


_gbl_object_types = None


def ObjectTypes():
    """This returns the list of objects types defined as directories.
    Many of them are CIM types, as described by DMTF: https://www.dmtf.org/standards/cim/cim_schema_v2510
    Many types are added, because CIM does not cover all the types needed by Survol.
    Each time it is possible, Survol-specific types are replaced by new, standard DMTF types.
    """
    global _gbl_object_types

    if _gbl_object_types is None:
        _gbl_object_types = set(_object_types_no_cache())
        # sys.stderr.write("ObjectTypes glbObjectTypes="+str(glbObjectTypes)+"\n")

    return _gbl_object_types

################################################################################

# These functions are used in scripts, to tell if it is usable or not.

isPlatformLinux = 'linux' in sys.platform
isPlatformDarwin = 'darwin' in sys.platform
isPlatformWindows = 'win32' in sys.platform


def UsableLinux(entity_type, entity_ids_arr):
    """Linux only
    This function is used in CGI scripts to define when a script can be used or not.
    When displaying an object, Survol looks for the CGI scripts which is related to it,
    that is, which can be run with the object parameters.
    Such a script can only in the directory of the class of the object.
    Another condition to meet is that the script must be "usable" for this platform,
    if some libraries are available etc...
    This is formalised by having in each script, an optional function called "Usable",
    which returns a boolean.
    Some "Usable" functions are very common, for example if a cript can be run on Linux or Windows etc...

    It is also possible to set a Usable function in a __init__.py file, and then it applies
    to all scripts of the directory and sub-directories."""
    return isPlatformLinux


def UsableWindows(entity_type, entity_ids_arr):
    """Windows only"""
    return isPlatformWindows


# Tells if a file is executable code or library.
# TODO: This function should be moved to CIM_DataFile/__init__.py
def UsableWindowsBinary(entity_type, entity_ids_arr):
    """Windows executable or code file"""
    if not UsableWindows(entity_type, entity_ids_arr):
        return False
    full_file_name = entity_ids_arr[0]
    if os.path.isdir(full_file_name):
        return False
    filename, file_extension = os.path.splitext(full_file_name)
    # TODO: Must add library type for ELF and PE ?
    return file_extension.upper() in [".EXE", ".DLL", ".COM", ".OCX", ".SYS", ".ACM", ".BPL", ".DPL"]


# Applies for nm, dll, elftools.
def UsableLinuxBinary(entity_type, entity_ids_arr):
    """Linux executable or code file"""
    if not UsableLinux(entity_type, entity_ids_arr):
        return False
    full_file_name = entity_ids_arr[0]
    if os.path.isdir(full_file_name):
        return False
    filename, file_extension = os.path.splitext(full_file_name)
    # TODO: Must add library type for ELF and PE ?
    if file_extension in [".so", ".lib"]:
        return True
    # TODO: Finish this. Use "magic" module ??
    return True


def check_program_exists(program_name):
    try:
        return check_program_exists.dict_program_to_existence[program_name]
    except KeyError:
        does_exist = _check_program_exists_nocache(program_name)
        check_program_exists.dict_program_to_existence[program_name] = does_exist
    return does_exist
check_program_exists.dict_program_to_existence = {}


def _check_program_exists_nocache(program_name):

    """
    This checks that an executable is in the current path and can be started without error.

    It might be used for perl, doxygen, iostat.
    """
    # TODO: Use a cache to do these tests once only.

    if os.path.isfile(program_name):
        # "where 'the full python path" does not work on Windows, therefore this specific test.
        # Also, it is more specific.
        return program_name

    logging.info("program_name=%s" % program_name)
    return _where_command(program_name)


def _where_command(program_name):
    if isPlatformWindows:
        test_command = ["where", program_name]
    elif isPlatformLinux or isPlatformDarwin:
        test_command = ["which", program_name]
    else:
        pass
    popen_object = subprocess.Popen(test_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    test_stdout_output, test_stderr = popen_object.communicate()
    if test_stderr:
        logging.info("test_stderr=%s" % test_stderr)
        return None
    full_path = test_stdout_output.strip()
    logging.info("full_path=%s" % full_path)
    return full_path


def is_snapshot_behaviour():
    """
    Used by scripts named like events_feeder_*.py which can write a continuous flow of events.
    They also must be able to run in snapshot mode, by default, and return RDF triples.
    """

    try:
        # Maybe this is started form the command line when testing.
        query_string = os.environ["QUERY_STRING"]
    except KeyError:
        query_string = ""

    logging.debug("is_snapshot_behaviour QUERY_STRING=%s" % query_string)
    is_snapshot = "mode=" + "daemon" not in query_string
    if is_snapshot:
        logging.debug("In snapshot mode")
    else:
        logging.debug("Not in snapshot mode")
    return is_snapshot


################################################################################


def HierarchicalFunctionSearchNoCache(type_without_ns, g_func_name):
    """
    For example gFuncName="Graphic_shape" etc... This seeks for a function in this name.
    This searches in several modules, starting with the module of the entity,
    then the upper module etc...
    """

    # For the first loop it takes the entire string.
    last_dot = len(type_without_ns)
    while last_dot > 0:
        chopped_entity_type = type_without_ns[:last_dot]

        # Load the module of this entity to see if it defines the graphic function.
        entity_module = GetEntityModule(chopped_entity_type)

        if entity_module:
            try:
                g_func_addr = getattr(entity_module, g_func_name)
                return g_func_addr
            except AttributeError:
                pass

        # Then try the upper level module.
        last_dot = type_without_ns.rfind(".", 0, last_dot)

    return None


# This caches the result of HierarchicalFunctionSearchNoCache()
_dict_hierarchical_function_search = {}


# TODO: This is similar to Python inheritance.
# TODO: Reuse the CIM hierarchy of classes.
# TODO: Difficulty is that all scripts must be changed.
# TODO: This is discussed here:
# https://softwareengineering.stackexchange.com/questions/298019/how-to-achieve-inheritance-when-using-just-modules-and-vanilla-functions-in-pyth
def HierarchicalFunctionSearch(type_without_ns, function_name):
    global _dict_hierarchical_function_search
    # Safety check.
    if type_without_ns.find(".") >= 0:
        raise "HierarchicalFunctionSearch Invalid type_without_ns=%s" % type_without_ns

    type_without_ns = type_without_ns.replace("/", ".")

    try:
        return _dict_hierarchical_function_search[function_name][type_without_ns]
    except KeyError:
        func_obj = HierarchicalFunctionSearchNoCache(type_without_ns, function_name)
        try:
            _dict_hierarchical_function_search[function_name][type_without_ns] = func_obj
        except KeyError:
            _dict_hierarchical_function_search[function_name] = {type_without_ns : func_obj}
        return func_obj


################################################################################

# This describes for each entity type, the list of parameters names needed
# to define an object of this class. For example:
# "dbus/connection"     : ( ["Bus","Connect"], ),
# "dbus/interface"      : ( ["Bus","Connect","Obj","Itf"], ),
# "symbol"              : ( ["Name","File"], ), # Must be defined here, not in the module.
_local_ontology = {
}

# The key must match the DMTF standard. It might contain a namespace.
# TODO: Replace this by a single lookup in a single dict
# TODO: ... made of localOntology added to the directory of types.
#
# NOTE: WMI flags the keys attributes, which are part of the path.
# https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/key-qualifier
# The Key qualifier indicates whether the property is part of the namespace handle.
# If more than one property has the Key qualifier,
# then all such properties collectively form the key (a compound key).
# When taken together, the key properties must supply a unique reference for each class instance.
#
# OpenLMI stores the definition of files in XML format:
# /var/lib/Pegasus/repository/root#cimv2/classes/CIM_Process.CIM_EnabledLogicalElement
#
# <PROPERTY NAME="Handle"  CLASSORIGIN="CIM_Process" TYPE="string">
#   <QUALIFIER NAME="Key" TYPE="boolean" OVERRIDABLE="false">
#     <VALUE>TRUE</VALUE>
#   </QUALIFIER>
# </PROPERTY>
#
# OpenPegasus does not do the same. See the file: CIM_Process.mof : All attributes are keys
#      [Key, Description ( "..."),
#       MappingStrings { "MIF.DMTF|Process Information|001.1" }]
#   string Handle;
#
# Conclusions:
# - There is no unique representation of the CIM classes.
# - They do not represent keys the same way.
# => Conclusion: It makes sense that Survol has its own representation.
#


def OntologyClassKeys(entity_type):
    # sys.stderr.write("OntologyClassKeys entity_type=%s Caller=%s\n"%(entity_type, sys._getframe(1).f_code.co_name))

    try:
        # TODO: If cannot find it, load the associated module and retry.
        return _local_ontology[entity_type][0]
    except KeyError:
        pass

    # Maybe the ontology is defined in the related module if it exists.
    entity_module = GetEntityModule(entity_type)
    if entity_module:
        try:
            entity_ontology_all = entity_module.EntityOntology()
            _local_ontology[entity_type] = entity_ontology_all
            return entity_ontology_all[0]
        except AttributeError:
            pass

    # It does not have a ontology, so it is a domain.
    _local_ontology[entity_type] = ([],)
    return []


def EntityIdToArray(entity_type, entity_id):
    """Used for calling ArrayInfo. The order of arguments is strictly the ontology's.
    It extracts the values of the ontology parameters and returns them in a list."""
    onto_keys = OntologyClassKeys(entity_type)
    #sys.stderr.write("lib_util.EntityIdToArray entity_type=%s entity_id=%s\n"%(entity_type,entity_id))
    dict_ids = SplitMoniker(entity_id)
    # sys.stderr.write("EntityIdToArray dict_ids=%s\n" % ( str(dict_ids) ) )
    # For the moment, this assumes that all keys are here.
    # Later, drop this constraint and allow WQL queries.
    try:
        def decode_cgi_arg(a_key):
            a_val_raw = dict_ids[a_key]
            try:
                val_decod = a_key.ValueDecode(a_val_raw)
                return val_decod
            except AttributeError:
                return urllib_unquote(a_val_raw)
                # return a_val_raw
        return [decode_cgi_arg(a_key) for a_key in onto_keys]
    except KeyError:
        gblLogger.error("EntityIdToArray missing key: type=%s id=%s onto=%s", entity_type, entity_id, str(onto_keys))
        raise


################################################################################


# Adds a key value pair at the end of the url with the right delimiter.
# TODO: Checks that the argument is not already there.
# TODO: Most of times, it is used for changing the mode.
def _concatenate_cgi_argument(url, keyvalpair):
    if url.rfind('?') == -1:
        return url + "?" + keyvalpair
    else:
        return url + "&" + keyvalpair


def UrlNoAmp(url):
    return url.replace("&amp;", "&").replace("&amp;", "&")

################################################################################


def request_uri_with_mode(other_mode):
    """In an URL, this replace the CGI parameter "http://....?mode=XXX" by "mode=YYY".
    If there is no such parameter, then it is removed. If the input parameter is
    an empty string, then it is removed from the URLs.
    Used for example as the root in entity.py, obj_types.py and class_type_all.py.
    """

    # When in merge_scripts.py for merging several scripts,
    # the request uri is prefixed by a host:
    # HttpPrefix()=http://myhost-hp:8000
    # RequestUri()=http://myhost-hp:80/Survol/survol/entity.py?xid=CIM_Process.Handle=1900
    str_request_uri = RequestUri()

    # strRequestUri=/survol/print_internal_data_as_json.py
    if str_request_uri.startswith("http"):
        script = str_request_uri
    else:
        script = HttpPrefix() + str_request_uri
    return url_mode_replace(script, other_mode)


def url_mode_replace(script, other_mode):
    """ In an url, replaces, removes or adds the value of the argument "mode".
    This is a key argument for CGI scripts. """

    mtch_url = re.match(r"(.*)([\?\&])mode=[^\&]*(.*)", script)

    if other_mode:
        if mtch_url:
            updated_url = mtch_url.group(1) + mtch_url.group(2) + "mode=" + other_mode + mtch_url.group(3)
        else:
            updated_url = _concatenate_cgi_argument(script, "mode=" + other_mode)
    else:
        # We want to remove the mode.
        if mtch_url:
            if mtch_url.group(2) == '?':
                # "mode" IS the first argument.
                if mtch_url.group(3):
                    updated_url = mtch_url.group(1) + "?" + mtch_url.group(3)[1:]
                else:
                    updated_url = mtch_url.group(1)
            else:
                # "mode" is NOT the first argument.
                updated_url = mtch_url.group(1) + mtch_url.group(3)
        else:
            # Nothing to do because it has no cgi arguments.
            updated_url = script

    # TODO: PROBLEMS IF THE URL CONTAINS BACKSLASHES SUCH AS HERE:
    # "http://127.0.0.1:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3DC%3A\Program%20Files%20%28x86%29\NETGEAR\WNDA3100v3\WNDA3100v3.EXE"
    return updated_url


def RootUri():
    calling_url = request_uri_with_mode("")
    calling_url = calling_url.replace("&", "&amp;")
    logging.debug("RootUri calling_url=%s", calling_url)
    return NodeUrl(calling_url)

################################################################################


# https://developer.mozilla.org/fr/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
def get_url_mode(url):
    """Extracts the mode from an URL or QUERY_STRING."""

    # Maybe it contains a MIME type: application/java-archive,
    # application/vnd.ms-powerpoint, audio/3gpp2, application/epub+zip

    # First argument, if QUERY_STRING, not a complete URL.
    mtch_url = re.match(r"mode=([^\&]*).*", url)
    if mtch_url:
        return mtch_url.group(1)
    # After the arguments delimiter, or in a URL.
    mtch_url = re.match(r".*[\?\&]mode=([^\&]*).*", url)
    if mtch_url:
        return mtch_url.group(1)
    return ""


def GuessDisplayMode():
    """The display mode can come from the previous URL or from a CGI environment.
    The previous url is needed when the current is "edit", that is, editing the CGI arguments.
    """

    # These are only the arguments, not an URL.
    query_string = os.environ["QUERY_STRING"]
    query_mode = get_url_mode(query_string)
    if query_mode != "":
        return query_mode

    try:
        # HTTP_REFERER=http://127.0.0.1/PythonStyle/print.py?mode=xyz
        referer = os.environ["HTTP_REFERER"]
        # This is a full URL.
        mode_referer = get_url_mode(referer)
        # If we come from the edit form, we should not come back to id.
        # TODO: HOW CAN WE COME BACK TO THE FORMER DISPLAY MODE ??
        if mode_referer != "":
            if mode_referer == "edit":
                # TODO: Should restore the original edit mode.
                # enter_edition_mode
                return ""
            else:
                return mode_referer

    except KeyError:
        pass

    mode = ""
    return mode

################################################################################


def SplitMoniker(xid):
    """The input string is an entity_id: "key1=val1&key2=val2&key3=val3",
    i.e. what comes after "xid=<class>." in an object URL.
    This returns a dictionary of key-values.
    """

    splt_lst = re.findall(r'(?:[^,"]|"(?:\\.|[^"])*")+', xid)

    # sys.stderr.write("SplitMoniker splt_lst=%s\n" % ";".join(splt_lst) )

    resu = dict()
    for splt_wrd in splt_lst:
        mtch_equal_quote = re.match(r'([A-Z0-9a-z_]+)="(.*)"', splt_wrd)
        if mtch_equal_quote:
            # If there are quotes, they are dropped.
            resu[mtch_equal_quote.group(1)] = mtch_equal_quote.group(2)
        else:
            mtch_equal_no_quote = re.match(r'([A-Z0-9a-z_]+)=(.*)', splt_wrd)
            if mtch_equal_no_quote:
                resu[mtch_equal_no_quote.group(1)] = mtch_equal_no_quote.group(2)

    # sys.stderr.write("SplitMoniker resu=%s\n" % str(resu) )

    return resu


def SplitMonikToWQL(moniker_to_split, class_name):
    """Builds a WQL (WMI Query Language) query from a Moniker.
    This allows to search for an object in the CIM repository,
    whatever the attribute values are, or if it is a Survol object."""
    gblLogger.debug("SplitMonikToWQL splitMonik=[%s]", str(moniker_to_split))
    a_qry = 'select * from %s' % class_name
    qry_delim = "where"
    for qry_key in moniker_to_split:
        qry_val = moniker_to_split[qry_key]
        a_qry += ' %s %s="%s"' % (qry_delim, qry_key, qry_val)
        qry_delim = "and"
    return a_qry


def Base64Encode(input_text):
    if is_py3:
        if isinstance(input_text, bytes):
            txt_to_b64_encode = input_text
        else:
            txt_to_b64_encode = input_text.encode('utf-8')
        return base64.urlsafe_b64encode(txt_to_b64_encode).decode('utf-8')
    else:
        return base64.urlsafe_b64encode(input_text)


def Base64Decode(input_text):
    """
    The padding might be missing which is not a problem:
    https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
    """
    missing_padding = len(input_text) % 4

    try:
        if is_py3:
            if missing_padding != 0:
                input_text += '=' * (4 - missing_padding)
            resu = base64.urlsafe_b64decode(input_text.encode('utf-8')).decode('utf-8')
        else:
            if missing_padding != 0:
                input_text += b'=' * (4 - missing_padding)
            resu = base64.urlsafe_b64decode(str(input_text))
        return resu
    except Exception as exc:
        gblLogger.error("CANNOT DECODE: symbol=(%s):%s", input_text, str(exc))
        return input_text + ":" + str(exc)


def split_url_to_entity(calling_url_node):
    """This receives an URL and parses it.
    Input examples:
    http://LOCAL_MODE:80/LocalExecution/sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py?xid=Win32_UserAccount.Domain%3Dthe_machine%2CName%3Drchateau"
    "http://the_machine:8000/survol/sources_types/CIM_Directory/doxygen_dir.py?xid=CIM_Directory.Name%3DD%3A"
    """

    # This might be a rdflib.term.URIRef which is converted straightforward.
    calling_url = str(calling_url_node)
    assert isinstance(calling_url, str), "Type should not be %s" % str(type(calling_url))
    parse_url = survol_urlparse(calling_url)
    query = parse_url.query

    params = parse_qs(query)
    xid_param = params['xid'][0]
    entity_type, entity_id, entity_host = ParseXid(xid_param)
    entity_id_dict = SplitMoniker(entity_id)

    return parse_url.path, entity_type, entity_id_dict


################################################################################


# Different stream behaviour due to string vs binary.
if is_py3:
    _output_http = sys.stdout.buffer
else:
    _output_http = sys.stdout

################################################################################


class OutputMachineCgi:
    """This is for WSGI compatibility."""
    def __init__(self):
        pass

    def HeaderWriter(self, mime_type, extra_arguments=None):
        gblLogger.debug("OutputMachineCgi.WriteHeadContentType:%s", mime_type)
        _http_header_classic(_output_http, mime_type, extra_arguments)

    def OutStream(self):
        return _output_http


# WSGI changes this to another object with same interface.
# Overriden in wsgiserver.py.
globalOutMach = OutputMachineCgi()

################################################################################

# This parameter in the display page of an object (entity.py),
# indicates if all scripts which can operate on this object, must be displayed,
# whether they can work or not.
# By default, it is False.
# For example, a script running on a Windows platform should not be displayed
# when running on Linux. Or if a specific Python module is needed,
# scripts using it should not be displayed. Same if the script has a syntax
# error. By setting this flag, it is easy to understand which scripts
# could be used and why they are not displayed.
paramkeyShowAll = "Show all scripts"

################################################################################


def get_default_output_destination():
    """Default destination for the RDF, HTML or SVG output."""
    return globalOutMach.OutStream()


def SetGlobalOutMach(outmach_something):
    global globalOutMach
    globalOutMach = outmach_something


# environ["SERVER_SOFTWARE"] = "WSGIServer/0.2"
# This must be calculated each time because the WSGI server sets this environment
# variable when an URL is loaded, after module init.
is_wsgi_server_data = None


def is_wsgi_server():
    global is_wsgi_server_data
    if not is_wsgi_server_data:
        try:
            is_wsgi_server_data = os.environ["SERVER_SOFTWARE"].startswith("WSGIServer")
        except KeyError:
            # FIXME: This is wrong, because it assumes that default server is WSGI.
            is_wsgi_server_data = "DefaultServerSoftware"
    return is_wsgi_server_data


def is_apache_server():
    return os.environ["SERVER_SOFTWARE"].startswith("Apache/")


def WrtAsUtf(input_str):
    """
    Depending if the stream is a socket, a file or standard output,
    if Python 2 or 3, Windows or Linux, some complicated tests or conversions are needed.
    This writes to:
    - Apache socket.
    - WSGI stream.
    - lib_client stream.
    - CGI output.
    """

    # FIXME: Should always send bytes (Py3) or str (Py2)
    my_output_stream = get_default_output_destination()
    try:
        my_output_stream.write(input_str)
    except:
        try:
            my_output_stream.write(input_str.encode('latin1'))
        except Exception as exc:
            sys.stderr.write("WrtAsUtf type=%s my_output_stream=%s caught %s\n"
                             % (type(input_str), type(my_output_stream), exc))


# contentType = "text/rdf", "text/html", "image/svg+xml", "application/json" etc...
def _http_header_classic(out_dest, content_type, extra_args=None):
    # sys.stderr.write("HttpHeader:%s\n"%content_type)
    # TODO: out_dest should always be the default output.

    stri = "Content-Type: " + content_type + "; charset=utf-8\n"
    if extra_args:
        # extra_args in a array of key-value tuples.
        # The order is preserved, and the same property can appear several times.
        for key_value in extra_args:
            stri += "%s: %s\n" % (key_value[0], key_value[1])
    stri += "\n"

    # Python 3.2
    try:
        # WSGI server and Py3, Apache and Py2.
        out_dest.write(stri)
        return
    except TypeError:
        pass
    # This is needed for the CGI server and Python 3.
    out_dest.write(stri.encode())


def WrtHeader(mime_type, extra_args=None):
    globalOutMach.HeaderWriter(mime_type, extra_args)

################################################################################


def _get_entity_module_without_cache_no_catch(entity_type):
    # Here, we want: "sources_types/Azure/location/__init__.py"
    # Example: entity_type = "Azure.location"
    # This works.
    # entity_module = importlib.import_module( ".subscription", "sources_types.Azure")

    entity_type_split = entity_type.split("/")
    if len(entity_type_split) > 1:
        entity_package = "sources_types." + ".".join(entity_type_split[:-1])
        entity_name = "." + entity_type_split[-1]
    else:
        entity_package = "sources_types"
        entity_name = "." + entity_type
    if (sys.platform.startswith("win32") and sys.version_info >= (3, 2) and sys.version_info < (3, 3) ) \
    or (sys.platform.startswith("lin") and sys.version_info >= (3, 2) ):
        entity_module = importlib.import_module(entity_package + entity_name)
    else:
        entity_module = importlib.import_module(entity_name, entity_package)
    return entity_module


def _get_entity_module_without_cache(entity_type):

    # Temporary hack to avoid an annoying warning message. This type of entity is used for Survol scripts
    # which return information. It is usefull to display them, so they need a special type,
    # not only as plain files, but also as Survol scripts.
    if entity_type == "provider_script":
        return None

    try:
        return _get_entity_module_without_cache_no_catch(entity_type)
    except ImportError as exc:
        gblLogger.error("_get_entity_module_without_cache entity_type=%s Caught:%s", entity_type, exc)
        return None


# So we try to load only once.
_cache_entity_to_module = {"": None}


def GetEntityModuleNoCatch(entity_type):
    """
    If it throws, the exception is not hidden.
    If it does not throw, then try to load the module.
    """

    # Do not throw KeyError exception.
    if entity_type in _cache_entity_to_module:
        return _cache_entity_to_module[ entity_type]

    entity_module = _get_entity_module_without_cache_no_catch(entity_type)
    _cache_entity_to_module[ entity_type] = entity_module
    return entity_module


# Maybe we could return an array because of heritage ?
# Or:  GetEntityModuleFunction(entity_type,functionName):
# ... which would explore from bottom to top.
def GetEntityModule(entity_type):
    try:
        # Might be None if the module does not exist.
        return _cache_entity_to_module[entity_type]
    except KeyError:
        pass
    entity_module = _get_entity_module_without_cache(entity_type)
    _cache_entity_to_module[entity_type] = entity_module
    return entity_module


def GetScriptModule(current_module, fil):
    """This loads a script as a module. Example:
    currentModule="sources_types.win32" fil="enumerate_top_level_windows.py" """
    logging.debug("current_module=%s fil=%s", current_module, fil)
    if not fil.endswith(".py"):
        logging.error("GetScriptModule module=%s fil=%s not a Python script", current_module, fil)
        return None
    file_base_name = fil[:-3] # Without the ".py" extension.
    if is_py3:
        # Example: importlib.import_module("sources_top.Databases.mysql_processlist")
        #logging.debug("currentModule=%s fil=%s subClass=%s",currentModule,fil,subClass)
        if current_module:
            imported_mod = importlib.import_module(current_module + "." + file_base_name)
        else:
            imported_mod = importlib.import_module(file_base_name)
    else:
        if current_module:
            logging.debug("GetScriptModule file_base_name=%s currentModule=%s", file_base_name, current_module)
            imported_mod = importlib.import_module("." + file_base_name, current_module)
        else:
            imported_mod = importlib.import_module(file_base_name)
    logging.debug("current_module=%s import OK", current_module)
    return imported_mod

################################################################################


def module_doc_string(imported_module, fil_default_text):
    """
        Returns the doc string of a module as a literal node. Possibly truncated
        so it can be displayed.
    """
    try:
        doc_modu_all = imported_module.__doc__
        if doc_modu_all:
            doc_modu_all = doc_modu_all.strip()
        # Take only the first non-empty line.
        doc_modu_split = doc_modu_all.split("\n")
        doc_modu = None
        for doc_modu in doc_modu_split:
            if doc_modu:
                # Arbitrary truncation string length.
                max_len = 40
                if len(doc_modu) > max_len:
                    doc_modu = doc_modu[0:max_len] + "..."
                break
    except:
        doc_modu = ""

    if not doc_modu:
        # If no doc available, just transform the file name.
        doc_modu = fil_default_text.replace("_", " ").capitalize()

    node_module = NodeLiteral(doc_modu)

    return node_module


def DirDocNode(arg_dir, the_dir):
    """
    This creates a non-clickable node. The text is taken from __doc__ if it exists,
    otherwise the file name is 'beautifuled'.
    """

    full_module = arg_dir + "." + the_dir

    try:
        imported_mod = importlib.import_module(full_module)
    except ImportError:
        return None

    # Add three characters otherwise it is truncated just like a Python file extension.
    return module_doc_string(imported_mod, the_dir)


def _append_not_none_hostname(script, hostname):
    str_url = uriRoot + script
    if hostname:
        # The string "portal" is just there to have a nice title.
        str_url += xidCgiDelimiter + hostname + "@portal."
    return str_url


def UrlPortalWbem(hostname=None):
    """Point to the WBEM portal for a given machine."""
    str_url = _append_not_none_hostname('/portal_wbem.py', hostname)
    gblLogger.debug("UrlPortalWbem str_url=%s", str_url)
    node_portal = NodeUrl(str_url)
    return node_portal


def UrlPortalWmi(hostname=None):
    """Point to the WMI portal for a given machine."""
    str_url = _append_not_none_hostname('/portal_wmi.py', hostname)
    node_portal = NodeUrl(str_url)
    return node_portal


def SplitTextTitleRest(title):
    """
    This is used to split a string made of several lines separated by a "\n",
    following multi-line DocString convention.
    "Multi-line docstrings consist of a summary line just like a one-line docstring,
    followed by a blank line, followed by a more elaborate description.
    The summary line may be used by automatic indexing tools;
    it is important that it fits on one line and is separated from the rest of the docstring by a blank line.
    The summary line may be on the same line as the opening quotes or on the next line.
    The entire docstring is indented the same as the quotes at its first line (see example below)."
    The only difference is that the blank line is not needed, but can be there.
    """
    title_split = title.strip().split("\n")

    page_title_first = title_split[0].strip()
    page_title_rest = " ".join( title_split[1:] ).strip()

    return (page_title_first,page_title_rest)


def TimeStamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


# TODO: This should fetch more information from WMI or WBEM ?
# TODO: Check for double insertion.
# domainPredicate and rangePredicate are class names.
# TODO: The data type is not correct.
def append_property_survol_ontology(
        name_predicate,
        description_predicate,
        domain_predicate,
        range_predicate,
        map_attributes):
    if range_predicate:
        data_type = "ref:" + range_predicate # This is the WMI way to indicate a class.
    else:
        # Default type for scalar values for Survol.
        data_type = "survol_string"
    if not description_predicate:
        description_predicate = "Predicate %s" % name_predicate
    if name_predicate in map_attributes:
        assert isinstance(domain_predicate, str)
        map_attributes[name_predicate]["predicate_domain"].append(domain_predicate)
    else:
        map_attributes[name_predicate] = {
            "predicate_type": data_type,
            "predicate_description": description_predicate,
            "predicate_domain" : [domain_predicate],
            "predicate_range" : range_predicate }


# TODO: Should we get classes and properties descriptions from WMI and WBEM ?
def AppendClassSurvolOntology(entity_type, map_classes, map_attributes):
    """
    This receives a class name from Survol and translates it into a CIM class name.
    If this is a top-level class, then it is the same string.
    If this is hierarchical, there might be duplicates.
    To make thing simpler, slashes are translated into a dot.
    NOTE: A difference between Survol and CIM, is that survols carries the hierarchy of classes in their names,
    just like files.
    """
    def survol_class_to_cim(name_survol_class):
        return name_survol_class.replace("/", ".")

    idx = 0
    base_class = ""
    # Iteration on the base classes starting from the top.
    while idx >= 0:
        next_slash = entity_type.find("/", idx + 1)
        if next_slash == -1:
            intermed_type = entity_type
        else:
            intermed_type = entity_type[:next_slash]

        base_class_name_cim = survol_class_to_cim(base_class)
        class_name_cim = survol_class_to_cim(intermed_type)

        try:
            # This reloads all classes without cache because if it does not load
            # we want to see the error message.
            entity_module = GetEntityModuleNoCatch(entity_type)
            ent_doc = entity_module.__doc__
            if ent_doc:
                ent_doc = ent_doc.strip()
            else:
                ent_doc = "No %s module documentation" % entity_type
        except Exception as exc:
            ent_doc = "Error:"+str(exc)

        if class_name_cim == "":
            raise Exception("Empty class in AppendClassSurvolOntology: entity_type=%s", entity_type)
        map_classes[class_name_cim] = {"base_class": base_class_name_cim, "class_description": ent_doc}

        onto_list = OntologyClassKeys(entity_type)
        # We do not have any other information about ontology keys.
        for onto_key in onto_list:
            append_property_survol_ontology(onto_key, "Ontology predicate %s" % onto_key, class_name_cim, None, map_attributes)

        idx = next_slash


def extract_specific_ontology_survol():
    """This iterates on all the classes defined by Survol files tree,
    and returns two dictionaries which define classes and predicates,
    compatible with insertion into RDF triplestore."""
    map_classes = {}
    map_attributes = {}

    for entity_type in ObjectTypes():
        AppendClassSurvolOntology(entity_type, map_classes, map_attributes)

    return map_classes, map_attributes

##################################################################################


# FIXME: Survol scripts are not able to return objects,
# FIXME: but they natively create triples which can be fed into the graph:
# FIXME: Survol scripts just return the minimum set of data allowing to join with other clauses.
#
# FIXME: On the other hand, WMI returns objects but cannot natively create RDF triples.
# FIXME: Therefore, it makes sense to create triples from the objects.
def PathAndKeyValuePairsToRdf(grph, subject_path, dict_key_values):
    # Maybe this is a test mode.
    if not grph:
        return
    subject_path_node = NodeUrl(subject_path)

    for key, val in dict_key_values.items():
        grph.add((subject_path_node, key, val))


def __check_if_directory(the_dir):
    if os.path.isdir(the_dir):
        return standardized_file_path(the_dir)
    raise Exception("Not a dir:" + the_dir)


def get_temporary_directory():
    """The temp directory as specified by the operating system."""

    # TODO: The user "apache" used by httpd cannot write, on some Linux distributions, to the directory "/tmp"
    # https://blog.lysender.com/2015/07/centos-7-selinux-php-apache-cannot-writeaccess-file-no-matter-what/
    # This is a temporary fix. Maybe related to SELinux.
    try:
        if isPlatformLinux:
            # 'SERVER_SOFTWARE': 'Apache/2.4.29 (Fedora)'
            if os.environ["SERVER_SOFTWARE"].startswith("Apache/"):
                # This is a very specific hardcode for Primhill Computers demo machine.
                # 'HTTP_HOST': 'vps516494.ovh.net'
                if os.environ["HTTP_HOST"].startswith("vps516494."):
                    return "/home/rchateau/tmp_apache"
    except:
        pass

    try:
        # Maybe these environment variables are undefined for Apache user.
        return __check_if_directory(os.environ["TEMP"])
    except Exception:
        pass

    try:
        return __check_if_directory(os.environ["TMP"])
    except Exception:
        pass

    if isPlatformWindows:
        try:
            return __check_if_directory(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Temp"))
        except Exception:
            pass

        try:
            return __check_if_directory("C:/Windows/Temp")
        except Exception:
            pass

        return __check_if_directory("C:/Temp")
    else:
        return __check_if_directory("/tmp")


# This will not change during a process.
global_temp_directory = get_temporary_directory()


# TODO: Consider using the module tempfile.
class TmpFile:
    """Creates and automatically delete, a file and possibly a dir."""
    def __init__(self, prefix="tmp", suffix="tmp", subdir=None):
        proc_pid = os.getpid()
        curr_dir = global_temp_directory

        if subdir:
            custom_dir = "/%s.%d" % (subdir, proc_pid)
            curr_dir += custom_dir
            if not os.path.isdir(curr_dir):
                os.mkdir(curr_dir)
            else:
                # TODO: Cleanup ??
                pass
            self.TmpDirToDel = curr_dir
        else:
            self.TmpDirToDel = None

        if prefix is None or suffix is None:
            self.Name = None
            return

        self.Name = "%s/%s.%d.%s" % (curr_dir, prefix, proc_pid, suffix)
        logging.debug("tmp=%s", self.Name )

    def _remove_temp_file(self, fil_nam):
        if True:
            logging.debug("Deleting=%s", fil_nam)
            os.remove(fil_nam)
        else:
            logging.warning("NOT Deleting=%s", fil_nam)

    def __del__(self):
        try:
            if self.Name:
                self._remove_temp_file(self.Name)

            # Extra check, not to remove everything.
            if self.TmpDirToDel not in [None, "/", ""]:
                # Extra-extra-check: Delete only survol temporary files.
                assert os.path.basename(self.TmpDirToDel).startswith("survol_")
                logging.debug("About to del %s", self.TmpDirToDel)
                for root, dirs, files in os.walk(self.TmpDirToDel, topdown=False):
                    for name in files:
                        self._remove_temp_file(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                        pass
                os.rmdir(self.TmpDirToDel)

        except Exception as exc:
            logging.error("__del__.Caught: %s. TmpDirToDel=%s Name=%s", str(exc), str(self.TmpDirToDel), str(self.Name))
        return

