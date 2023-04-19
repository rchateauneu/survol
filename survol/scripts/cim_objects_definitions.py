"""
This contains the definitions of CIM objects and their containers.
These containers are filled when functions calls detect the creation
or handling of such an object.
This modules contains specialized containers for these objects,
which are later used to create a Dockerfile.
These are many common objects with the sub-packages found in survol/sources_types/*/
However, information related to the same class are not stored together, because:
- When monitoring a running binary with dockit, we wish to import as few code as possible.
- The sub-packages related to a class in survol/sources_types/*/ contain
  many scripts and a lot of code, with possibly a lengthy init.
- Even if the classes are the same, the needed features are different:
  Here, it stores actual information about an object, to model the running application.
"""

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Primhill Computers, 2018-2023"
__license__ = "GPL"
__maintainer__ = "Remi Chateauneu"
__email__ = "contact@primhillcomputers.com"

import os
import re
import io
import six
import sys
import json
import platform
import datetime
import socket
import shutil
import threading
import time
import collections
import rdflib
import logging

try:
    # This is for Python 2
    import urllib2
    import urllib
    urlencode_portable = urllib.urlencode
except ImportError:
    import urllib.request as urllib2
    import urllib.parse
    urlencode_portable = urllib.parse.urlencode

try:
    # This is optional when used from dockit, so dockit can be used
    # without any installation.
    import psutil
except ImportError:
    psutil = None

is_py3 = sys.version_info >= (3,)
is_platform_linux = sys.platform.startswith("linux")

################################################################################

def _decode_octal_escape_sequence(input_buffer):
    # An octal escape sequence consists of \ followed by one, two, or three octal digits.
    # The octal escape sequence ends when it either contains three octal digits already,
    # or the next character is not an octal digit.
    # For example, \11 is a single octal escape sequence denoting a byte with numerical value 9 (11 in octal),
    # rather than the escape sequence \1 followed by the digit 1.
    # However, \1111 is the octal escape sequence \111 followed by the digit 1.
    # In order to denote the byte with numerical value 1, followed by the digit 1,
    # one could use "\1""1", since C automatically concatenates adjacent string literals.
    # Note that some three-digit octal escape sequences may be too large to fit in a single byte;
    # this results in an implementation-defined value for the byte actually produced.
    # The escape sequence \0 is a commonly used octal escape sequence,
    # which denotes the null character, with value zero.
    # https://en.wikipedia.org/wiki/Escape_sequences_in_C

    # https://stackoverflow.com/questions/4020539/process-escape-sequences-in-a-string-in-python
    if is_py3:
        dec_buf = bytes(input_buffer, "utf-8").decode("unicode_escape")
    else:
        dec_buf = input_buffer.decode('string_escape')
    return dec_buf


################################################################################

# Buffers transferred with read() and write() are parsed to detect information
# about the running applications. There can be several types of parsers,
# indexed by a descriptive key: "SqlQuery" etc...
# TODO: There is not valid reason to load all buffer scanners in this file.
_buffer_scanners = {}

################################################################################

# This avoids the error:
# "sys.meta_path must be a list of import hooks"
# This module is needed for storing the generated data into a RDF file.
# TODO: This fails when a CGI script import something from survol/scripts,
# TODO: ... which at its turn imports something from survol/survol.
# TODO: Originally, all scripts in scripts should not have been dependent of the other
# TODO: modules like survol/lib_*.py , so they could be copied on any machine
# TODO: and do their work, especially dockit.py .
# TODO: However, some imports like lib_event.py or, in the future, lib_sql.py ,
# TODO: are necessary.
# TODO: On top of that, files in survol/scripts are now used as libraries
# TODO: for general scripts. This is not critical at all, but some files
# TODO: need to be moved at other places.

# TODO: UGLY LOGIC TO BE CHANGED.
if "../.." not in sys.path:
    sys.path.append("../..")
if ".." not in sys.path:
    sys.path.append("..")
if "../survol" not in sys.path:
    sys.path.append("../survol")
if "../../survol" not in sys.path:
    sys.path.append("../../survol")

try:
    from survol import lib_event
except:
    import lib_event

try:
    # This seems to work on Python 2 Linux but not Python 3
    from survol import lib_sql
except ImportError:
    # Do not write error message to stdout.
    logging.warning("Cannot import optional module lib_sql")
    lib_sql = None

if __package__:
    from . import naming_conventions
else:
    import naming_conventions

local_standardized_file_path = naming_conventions.standardized_file_path

standardized_file_path_syntax_only = naming_conventions.standardized_file_path_syntax_only


def standardize_object_attributes(cim_class_name, cim_arguments):
    """Some very specific rules to format a file or directrory name:
    Backslashes are replaced by slashes. Symbolic links are dereferenced."""
    if cim_class_name in ["CIM_DataFile", "CIM_Directory"]:
        path_file = cim_arguments["Name"]
        cim_arguments["Name"] = local_standardized_file_path(path_file)


################################################################################

if lib_sql:
    # This creates the SQL queries scanner, it needs Survol code.
    dict_regex_sql = lib_sql.SqlRegularExpressions()

    dict_regex_sql_compiled = {
        rgx_key: re.compile(dict_regex_sql[rgx_key], re.IGNORECASE)
        for rgx_key in dict_regex_sql
    }

    # This returns a list of SQL queries.
    def _raw_buffer_sql_query_scanner(input_buffer):
        # The regular expressions are indexed with a key such as "INSERT", "SELECT" etc...
        # which gives a hint about what the query does.
        # This creates a dictionary mapping the RDF property to the compiled regular expression.
        # Also, the regular expressions are compiled for better performance.

        lst_queries = []

        for rgx_key in dict_regex_sql_compiled:
            compiled_rgx = dict_regex_sql_compiled[rgx_key]
            matched_sqls = compiled_rgx.findall(input_buffer)
            if matched_sqls:
                lst_queries += matched_sqls

        # TODO: For the moment, we just print the query. How can it be related to a database ?
        # How can we get the database connection ?
        # If attaching to a running process, this is even impossible.
        # TODO: We can create symbolic database connection: At least we known the server name.
        # We can associate one connection to each socket or pipe where a SQL query could be found.
        # ... possibly list the connections as CIM objects.
        # An extra regular expression on the buffer, or some test on the SQL query,
        # might imply the database type. This is not very important because the database connection
        # is an obvious information
        # for the user.
        return lst_queries

    _buffer_scanners["SqlQuery"] = _raw_buffer_sql_query_scanner

################################################################################


class BufferConcatenator:
    """
    When strace or ltrace display a call to read() and write(), they also display
    a fragment of the transferred bytes. It is needed to try to rebuild the entire
    sequence between the opening and the closing, because some important information
    that we want to parse, might be truncated.
    Beware, there are severe limitations: The amount of displayed bytes is limited,
    and it does not take into account fseek().
    """
    def __init__(self):
        self.m_currentBuffer = None
        self.m_parsedData = None

    def __analyse_io_buffer(self, a_buffer):
        for scanner_key in _buffer_scanners:
            scanner_function = _buffer_scanners[scanner_key]

            # This returns a list of strings.
            # TODO: In the future, this might return CIM objects.
            lst_results = scanner_function(a_buffer)

            if lst_results:
                if self.m_parsedData == None:
                    self.m_parsedData = {}
                if scanner_key in self.m_parsedData:
                    self.m_parsedData[scanner_key] += lst_results
                else:
                    self.m_parsedData[scanner_key] = lst_results

    def has_parsed_data(self):
        return self.m_parsedData != None

    def parsed_data_to_XML(self, strm, margin, direction):
        if self.m_parsedData:
            submargin = margin + "    "
            for scanner_key in self.m_parsedData:
                # TODO: Have a specific tag for the list.
                scanner_key_set = scanner_key + "_List"
                strm.write("%s<%s direction='%s'>\n" % (margin, scanner_key_set, direction))
                scanner_val = self.m_parsedData[scanner_key]
                for scanResult in scanner_val:
                    strm.write("%s<%s>%s</%s>\n" % (submargin, scanner_key, scanResult, scanner_key))
                strm.write("%s</%s>\n" % (margin, scanner_key_set))

    def append_io_buffer(self, a_fragment, sz_fragment=0):
        """
        This receives all read() and write() buffers displayed by strace or ltrace,
        decodes them and tries to rebuild a complete logical message if it seems to be truncated.
        It then analyses the logical pieces.
        """
        decoded_fragment = _decode_octal_escape_sequence(a_fragment)

        # Typical buffer size are multiple of 100x:
        #      256              100 #
        #      512              200 #
        #    12288             3000 #
        #    49152             c000 #
        #    65536            10000 #
        #   262144            40000 #

        is_segment = (
            ((sz_fragment % 0x100 == 0) and (sz_fragment <= 0x1000)) or
            ((sz_fragment % 0x1000 == 0) and (sz_fragment <= 0x10000)) or
            ((sz_fragment % 0x10000 == 0) and (sz_fragment <= 0x100000)) or
            (sz_fragment % 0x100000 == 0))

        if is_segment and (sz_fragment == len(decoded_fragment)):
            if self.m_currentBuffer:
                self.m_currentBuffer += decoded_fragment
            else:
                self.m_currentBuffer = decoded_fragment
        else:
            if self.m_currentBuffer:
                self.__analyse_io_buffer(self.m_currentBuffer)
                # Reuse memory.
                del self.m_currentBuffer
                self.m_currentBuffer = None

            self.__analyse_io_buffer(decoded_fragment)

################################################################################


G_FilesToPackagesCache = None

G_SameMachine = None

# This is a dictionary (indexed by processes) of dictionaries (indexed by files).
# It containes files accesses, which are object representing what happens
# to a file between its opening and closing by a process.
_cache_file_accesses = collections.defaultdict(dict)


class FileAccess:
    """
    This models an open/read-or-write/close access from a process to a file.
    The same process may access several times the same file, producing several FileAccess objects.
    If the same file is opened twice in the same process without being closed, behaviour is unspecified.
    This is displayed in XML as a single tag:
    <FileAccess OpenTime="" CloseTime="" etc... />
    """
    def __init__(self, obj_process, obj_data_file, open_flag):
        self.OpenTime = None
        self.CloseTime = None
        self.m_objectCIM_Process = obj_process
        self.m_objectCIM_DataFile = obj_data_file
        self.m_openFlag = open_flag

        obj_process.m_ProcessFileAccesses.append(self)
        obj_data_file.m_DataFileFileAccesses.append(self)

    def SetOpenTime(self, time_stamp):
        try:
            self.NumOpen += 1
        except AttributeError:
            self.NumOpen = 1
        if not self.OpenTime or (time_stamp < self.OpenTime):
            self.OpenTime = time_stamp

            if G_SameMachine:
                try:
                    fil_stat = os.stat(self.m_objectCIM_DataFile.Name)
                    self.OpenSize = fil_stat.st_size
                except:
                    pass

    def SetCloseTime(self, time_stamp):
        # Maybe the file was never closed.
        if not getattr(self, "CloseTime", 0) or (time_stamp < self.CloseTime):
            self.CloseTime = time_stamp

            if G_SameMachine:
                try:
                    fil_stat = os.stat(self.m_objectCIM_DataFile.Name)
                    self.CloseSize = fil_stat.st_size
                except:
                    pass

    def _analyze_new_buffer(self, is_read, buffer_size, a_buffer):
        """Calling on a IO buffer ot a file or something."""
        if not a_buffer:
            return

        # This does not apply to files.
        if self.m_objectCIM_DataFile.Name and CIM_DataFile.is_plain_file(self.m_objectCIM_DataFile.Name):
            return

        if is_read:
            try:
                self.m_bufConcatRead
            except AttributeError:
                self.m_bufConcatRead = BufferConcatenator()
            concat_buf = self.m_bufConcatRead
        else:
            try:
                self.m_bufConcatWrite
            except AttributeError:
                self.m_bufConcatWrite = BufferConcatenator()
            concat_buf = self.m_bufConcatWrite

        try:
            concat_buf.append_io_buffer(a_buffer, buffer_size)
        except Exception as exc:
            # Example: '[pid  5602] 19:59:20.590740 <... read resumed> "... end of read() content"..., 32768) = 4096 <0.037642>'
            logging.info("Cannot parse buffer:%s size=%s: file=%s %s" % (
                a_buffer,
                buffer_size,
                self.m_objectCIM_DataFile.Name,
                exc))
            # This is not a problem.

    def set_read_bytes_number(self, read_bytes_number, buffer_read):
        """This is called when reading a buffer from a file or something."""
        try:
            self.NumReads += 1
        except AttributeError:
            self.NumReads = 1
        try:
            self.BytesRead += read_bytes_number
        except AttributeError:
            self.BytesRead = read_bytes_number
        self._analyze_new_buffer(True, read_bytes_number, buffer_read)

    def set_written_bytes_number(self, written_bytes_number, buffer_write):
        """This is called when writing a buffer from a file or something."""
        try:
            self.NumWrites += 1
        except AttributeError:
            self.NumWrites = 1
        try:
            self.BytesWritten += written_bytes_number
        except AttributeError:
            self.BytesWritten = written_bytes_number
        self._analyze_new_buffer(False, written_bytes_number, buffer_write)

    def TagXML(self, strm, margin, displayed_from_process):
        strm.write("%s<Access" % margin)

        if displayed_from_process:
            if self.m_objectCIM_Process:
                strm.write(" Process='%s'" % self.m_objectCIM_Process.Handle)
        else:
            if self.m_objectCIM_DataFile:
                strm.write(" File='%s'" % self.m_objectCIM_DataFile.Name)

        if self.OpenTime:
            strm.write(" OpenTime='%s'" % _timestamp_to_str(self.OpenTime))
        if getattr(self, 'OpenSize', 0):
            strm.write(" OpenSize='%s'" % self.OpenSize)
        if self.CloseTime:
            strm.write(" CloseTime='%s'" % _timestamp_to_str(self.CloseTime))
        if getattr(self, 'CloseSize', 0):
            strm.write(" CloseSize='%s'" % self.CloseSize)
        if getattr(self, 'NumReads', 0):
            strm.write(" NumReads='%s'" % self.NumReads)
        if getattr(self, 'BytesRead', 0):
            strm.write(" BytesRead='%s'" % self.BytesRead)
        if getattr(self, 'NumWrites', 0):
            strm.write(" NumWrites='%s'" % self.NumWrites)
        if getattr(self, 'BytesWritten', 0):
            strm.write(" BytesWritten='%s'" % self.BytesWritten)

        acc_read = getattr(self, 'm_bufConcatRead', None)
        acc_write = getattr(self, 'm_bufConcatWrite', None)

        if (acc_read and acc_read.has_parsed_data()) or (acc_write and acc_write.has_parsed_data()):
            strm.write(" >\n")

            submargin = margin + "    "
            if acc_read and acc_read.has_parsed_data():
                acc_read.parsed_data_to_XML(strm, submargin, "Read")
            if acc_write and acc_write.has_parsed_data():
                acc_write.parsed_data_to_XML(strm, submargin, "Write")

            strm.write("%s</Access>\n" % margin)
        else:
            strm.write(" />\n")

    @staticmethod
    def lookup_file_access(obj_process, obj_data_file, open_flag):
        """The file must not be already opened."""
        global _cache_file_accesses
        assert _cache_file_accesses is not None

        try:
            fil_acc = _cache_file_accesses[obj_process][obj_data_file]
            if open_flag == "W":
                fil_acc.m_openFlag = "W"
        except KeyError:
            fil_acc = FileAccess(obj_process, obj_data_file, open_flag)
            _cache_file_accesses[obj_process][obj_data_file] = fil_acc
        return fil_acc

    @staticmethod
    def serialize_list_to_XML(strm, vec_files_accesses, margin, displayed_from_process):
        if not vec_files_accesses:
            return
        sub_margin = margin + "    "
        strm.write("%s<FileAccesses>\n" % margin)
        for filAcc in vec_files_accesses:
            filAcc.TagXML(strm, sub_margin, displayed_from_process)
        strm.write("%s</FileAccesses>\n" % margin)

################################################################################

# When replaying a session, it is not worth getting information about processes because they do not exist anymore.
G_ReplayMode = False

# The date where the test was run. Loaded from the ini file when replaying.
G_Today = None


def _timestamp_to_str(tim_stamp):
    # 0     tm_year     (for example, 1993)
    # 1     tm_mon      range [1, 12]
    # 2     tm_mday     range [1, 31]
    # 3     tm_hour     range [0, 23]
    # 4     tm_min      range [0, 59]
    # 5     tm_sec      range [0, 61]; see (2) in strftime() description
    # 6     tm_wday     range [0, 6], Monday is 0
    # 7     tm_yday     range [1, 366]
    # 8     tm_isdst    0, 1 or -1; see below

    # Today's date can change so we can reproduce a run.
    if tim_stamp:
        return G_Today + " " + tim_stamp
    else:
        return G_Today + " 00:00:00.000000"

################################################################################


class HttpTriplesClientNone(object):
    """This is the base of the classes which send events somewhere else.
    Events are about CIM objects (processes, file, sockets, anything detected by strace.
    These objects are described with an URL using CIM terminology and semantic web concepts.
    An event is a triple made of such an URL, a property, and a value which can be a literal value
    or the url of another CIM object.
    These events can be sent to:
    - A RDF file for further analysis.
    - A URL which might for example store these events in a RDF triples store.
    - Or a callback: This is used to store events in a local RDF triplestore, where they can be read
      by another process.
    """
    def http_client_shutdown(self):
        pass


class HttpTriplesClientFile(HttpTriplesClientNone):
    """If the server name is a file, the RDF content is instead stored to this file by the object destructor."""
    def __init__(self):
        self._events_graph = rdflib.Graph()
        print("G_UpdateServer=", G_UpdateServer, " IS FILE")

    def http_client_shutdown(self):
        print("HttpTriplesClientFile.http_client_shutdown G_UpdateServer=", G_UpdateServer)
        self._events_graph.serialize(destination=G_UpdateServer, format='xml')
        print("Stored RDF content to", G_UpdateServer)

    def enqueue_rdf_triple(self, rdf_triple):
        # Just append the triple, no need to synchronise.
        self._events_graph.add(rdf_triple)


def send_graph_to_url(input_graph, events_url):
    """This sends a rdflib Graph to an URL in RDF-XML format.
    It checks the output and returns the number of inserted triples."""

    # TODO: Ideally, should serialize the graph into the socket.
    bytes_stream = io.BytesIO()
    input_graph.serialize(destination=bytes_stream, format='xml')
    events_as_bytes = bytes_stream.getvalue()
    bytes_number = len(events_as_bytes)

    try:
        the_headers = {"Content-type": "application/xml:", 'Content-Length': bytes_number}
        req = urllib2.Request(events_url, headers=the_headers)
        urlopen_result = urllib2.urlopen(req, data=events_as_bytes, timeout=10.0)
    except Exception as server_exception:
        logging.error("Event server error=%s" % str(server_exception))
        raise

    server_response = urlopen_result.read()
    json_response = json.loads(server_response)
    if json_response['success'] != 'true':
        raise Exception("Event server error message=%s\n" % json_response['error_message'])
    received_triples_number = int(json_response['triples_number'])
    print("send_graph_to_url received_triples_number=%d\n" % received_triples_number)
    return received_triples_number


class HttpTriplesClientHttp(HttpTriplesClientNone):
    """This objects groups triples to send to the HTTP server, and periodically wakes up to send them."""
    def __init__(self):
        self._events_graph = rdflib.Graph()

        # Threaded mode does not work when creating the server in the same process.
        # For safety, this reverts to a simpler mode where the triples are sent
        # in block at the end of the execution.
        # TODO: Test this with thread mode.
        self._is_threaded_client = False

        if self._is_threaded_client:
            self._shared_lock = threading.Lock()
            self._client_thread = threading.Thread(target = self.run)
            # If leaving too early, some data might be lost.
            self._client_thread.daemon = True
            self._client_thread.start()

    def http_client_shutdown(self):
        print("HttpTriplesClientHttp.http_client_shutdown threaded=", self._is_threaded_client)
        self._push_triples_to_server()

    def _push_triples_to_server(self):
        """This sends the graph containing the events, to the HTTP server.
        This HTTP server can for example store them in a triplestore.
        """
        if self._is_threaded_client:
            self._shared_lock.acquire()
        # Take a reference to the graph and create a new one. The reference now cannot be changed and is safe.
        reference_to_graph = self._events_graph
        self._events_graph = rdflib.Graph()
        # Immediately unlocked so no need to wait for the url access.
        if self._is_threaded_client:
            self._shared_lock.release()

        if reference_to_graph:
            received_triples_number = send_graph_to_url(reference_to_graph, G_UpdateServer)
            if received_triples_number != len(reference_to_graph):
                raise Exception("Lost triples: %d != %d\n" % (received_triples_number, len(reference_to_graph)))

    def run(self):
        """This thread functor loops on the container of triples.
        It formats them in JSON and sends them to the URL of the events server."""
        assert self._is_threaded_client
        while True:
            time.sleep(2.0)
            self._push_triples_to_server()

    def enqueue_rdf_triple(self, rdf_triple):
        if self._is_threaded_client:
            self._shared_lock.acquire()
            self._events_graph.add(rdf_triple)
            self._shared_lock.release()
        else:
            self._events_graph.add(rdf_triple)


class HttpTriplesClientDaemon(HttpTriplesClientNone):
    """This calls function for each generated triple which represents an event.
    These events are inserted in a global RDF graph which can be access by CGI scripts,
    started on-demand by users. There is no need to store these events. """
    def enqueue_rdf_triple(self, rdf_triple):
        G_UpdateServer(rdf_triple)


def http_triples_client_factory():
    """Tests if this a output RDF file, or rather None or the URL of a Survol agent."""
    if G_UpdateServer:
        # This parameter is a function or a file name or an url.
        if callable(G_UpdateServer):
            return HttpTriplesClientDaemon()
        else:
            update_server_lower = G_UpdateServer.lower()
            server_is_http = update_server_lower.startswith(("http:", "https:"))
            if server_is_http:
                return HttpTriplesClientHttp()
            else:
                return HttpTriplesClientFile()
    else:
        return HttpTriplesClientNone()


# This is the Survol server which is notified of all updates
# of CIM objects. These updates can then be displayed in Survol Web clients.
# It must be a plain Web server to be hosted by Apache or IIS.
G_UpdateServer = None

################################################################################


# attr=AccessTime attrVal=1518262584.92 <type 'float'>
def _time_t_to_datetime(st_time_t):
    # Or utcfromtimestamp
    return datetime.datetime.strftime(datetime.datetime.fromtimestamp(st_time_t), "%H:%M:%S:%f")

################################################################################


def leaf_derived_classes(the_class):
    """This returns only leaf classes."""
    current_subclasses = the_class.__subclasses__()
    return set([sub_class for sub_class in current_subclasses if not leaf_derived_classes(sub_class)]).union(
        [sub_sub_class for sub_class in current_subclasses for sub_sub_class in leaf_derived_classes(sub_class)])


def _is_CIM(attr, attr_val):
    """
    CIM classes are defined as plain Python classes plus their attributes.
    Therefore, CIM attributes are mixed with Python ones.
    This function is a rule-thumb test to check if an attribute of a class
    is a CIM attribute. It works because there are very few non-CIM attributes.

    TODO: Consider not serializing class members.
    """
    return not callable(attr_val) and not attr.startswith(("__", "m_"))


def _is_time_stamp(attr):
    """
    This identifies CIM attribute which is date or time and must be displayed as such.
    For example "ns1:TerminationDate", "ns1:CreationDate"
    """
    return attr.find("Date") > 0 or attr.find("Time") > 0


class CIM_XmlMarshaller(object):
    """
    This is the base class of all CIM_xxx classes. It does the serialization
    into XML and also sends updates events to the Survol server if there is one.
    """
    def __init__(self):
        # TODO: Must set the class with rdfs:Class
        # TODO: Possibly self.__class__.__name__
        # TODO: See https://www.w3.org/TR/rdf-schema/#ch_class
        pass

    def plain_to_XML(self, strm, sub_margin):
        try:
            # Optional members order.
            # TODO: Why is it needed ?
            attr_extra = self.__class__.m_attributes_priorities
        except AttributeError:
            attr_extra = []

        start = len(attr_extra)
        enum_attrs = {}
        for elt in dir(self):
            enum_attrs[elt] = start
            start += 1

        start = 0
        for elt in attr_extra:
            enum_attrs[elt] = start
            start += 1

        dict_attrs = dict((val, key) for (key, val) in enum_attrs.items())
        for idx in sorted(dict_attrs.keys()):
            attr = dict_attrs[idx]
            try:
                attr_val = getattr(self, attr)
            except AttributeError:
                continue
            if _is_CIM(attr, attr_val):
                # FIXME: Not very reliable because it only tests the attribute name.
                if _is_time_stamp(attr):
                    # TODO : <ns1:AccessTime>23:30:15:900428</ns1:AccessTime>
                    # TODO: This should be something like : <ns1:FileMode rdf:datatype="http://www.w3.org/2001/XMLSchema#integer">33188</ns1:FileMode>
                    # TODO: See https://www.w3schools.com/xml/schema_dtypes_date.asp
                    attr_val = _timestamp_to_str(attr_val)
                if attr_val:
                    # No need to write empty strings.
                    # If attr_val is not an int, it is automatically converted to str.
                    strm.write("%s<%s>%s</%s>\n" % (sub_margin, attr, attr_val, attr))

    def http_update_request(self, the_subject, the_predicate, the_object):
        rdf_triple = lib_event.json_triple_to_rdf_triple(the_subject, the_predicate, the_object)
        G_httpClient.enqueue_rdf_triple(rdf_triple)

    def send_update_to_server(self, attr_nam, old_attr_val, attr_val):
        """For a given object and one of its attributes, this receives the former and the new value.
        """

        # In RDF, the subject is always an URL.
        # This string uniquely defines an object: It contains the class and the key-value pairs
        # of the properties of the ontology.
        the_subj_moniker = self.get_survol_moniker()

        # TODO: If the attribute is part of the ontology, just inform about the object creation.
        # TODO: Some attributes could be the moniker of another object.
        # TODO: AND THEREFORE, SEND LINKS, NOT ONLY LITERALS !!!
        # OTHERWISE NO EDGES !!

        if old_attr_val and isinstance(old_attr_val, CIM_XmlMarshaller):
            raise Exception("Not implemented yet")
            obj_moniker_old = old_attr_val.get_survol_moniker()
            # TODO: Possibly manage object deletions with: attrNamDelete = attr_nam + "?predicate_delete"
            self.http_update_request(the_subj_moniker, attr_nam, obj_moniker_old)

        # For example a file being opened by a process, or a process started by a user etc...
        # Then it is an object which will become a RDF url.
        if isinstance(attr_val, CIM_XmlMarshaller):
            obj_moniker = attr_val.get_survol_moniker()
            self.http_update_request(the_subj_moniker, attr_nam, obj_moniker)
        else:
            # Otherwise it is simply a literal.
            self.http_update_request(the_subj_moniker, attr_nam, attr_val)

    def __setattr__(self, attr_nam, attr_val):
        """Any object creation or update is broadcast to a Survol server.
        attr_nam is a string.
        attr_val is a literal, or an object deriving from CIM_XmlMarshaller. """

        # First, change the value, because it might be needed to calculate the moniker.
        try:
            old_attr_val = self.__dict__[attr_nam]
        except:
            old_attr_val = None

        self.__dict__[attr_nam] = attr_val

        if G_UpdateServer:
            # If the value did not change, no need to send an update.
            if old_attr_val != attr_val:
                if _is_CIM(attr_nam, attr_val):
                    self.send_update_to_server(attr_nam, old_attr_val, attr_val)

    @classmethod
    def DisplaySummary(cls, fd_summary_file, cim_key_value_pairs):
        pass

    @classmethod
    def XMLSummary(cls, fd_summary_file, cim_key_value_pairs):
        """Used to create a summary file of all created or updated objects in this run."""
        nam_class = cls.__name__
        margin = "    "
        sub_margin = margin + margin
        for obj_path, obj_instance in sorted(cls.m_G_map_cache_objects.items()):
            fd_summary_file.write("%s<%s>\n" % (margin, nam_class))
            obj_instance.plain_to_XML(fd_summary_file, sub_margin)
            fd_summary_file.write("%s</%s>\n" % (margin, nam_class))

    def get_survol_moniker(self):
        """
        This object has a class name, an ontology which is an ordered list
        of attributes names, and several attributes in the object itself.
        This method wraps the class name and these attributes and their values,
        into an object which is used to store an event related to this object.
        JSON escapes special characters in strings.
        """
        attributes_dict = {attribute_key: getattr(self, attribute_key) for attribute_key in self.cim_ontology_list}
        return self.__class__.__name__, attributes_dict

    def __repr__(self):
        mnk = self.__class__.__name__ + "." + ",".join(
            '%s="%s"' % (k, getattr(self, k)) for k in self.cim_ontology_list)
        return mnk

    @staticmethod
    def create_instance_from_class_name(cim_class_name, **cim_attributes_dict):
        cim_class_definition = _class_name_to_subclass[cim_class_name]
        attributes_list = [cim_attributes_dict[key] for key in cim_class_definition.cim_ontology_list]
        return cim_class_definition(*attributes_list)

################################################################################


# Read from a real process or from the ini file when replaying a session.
G_CurrentDirectory = u""


# The CIM_xxx classes are taken from Common Information Model standard.
# They share some properties and are adding more.

# class CIM_ComputerSystem : CIM_System
# {
#   string   Caption;
#   string   Description;
#   datetime InstallDate;
#   string   Status;
#   string   CreationClassName;
#   string   Name;
#   string   PrimaryOwnerContact;
#   string   PrimaryOwnerName;
#   string   Roles[];
#   string   NameFormat;
# }
class CIM_ComputerSystem(CIM_XmlMarshaller):
    def __init__(self, hostname):
        super(CIM_ComputerSystem, self).__init__()
        self.Name = hostname.lower()  # This is a convention.

        if not G_ReplayMode and psutil:
            vm = psutil.virtual_memory()
            self.VirtualMemoryTotal = vm[0]
            self.VirtualMemoryAvailable = vm[1]
            self.VirtualMemoryUsed = vm[3]
            self.VirtualMemoryFree = vm[4]

            try:
                cf = psutil.cpu_freq()
                if cf:
                    self.CpuCurrent = cf[0]
                    self.CpuMinimum = cf[1]
                    self.CpuMaximum = cf[2]
            except AttributeError as exc:
                logging.warning("AttributeError:%s" % exc)
            except NotImplementedError as exc:
                # cpu_freq is not implemented on WSL.
                logging.warning("AttributeError:%s" % exc)

    cim_ontology_list = ['Name']


#
# class CIM_OperatingSystem : CIM_LogicalElement
# {
#   string   Caption;
#   string   CreationClassName;
#   string   CSCreationClassName;
#   string   CSName;
#   sint16   CurrentTimeZone;
#   string   Description;
#   boolean  Distributed;
#   uint64   FreePhysicalMemory;
#   uint64   FreeSpaceInPagingFiles;
#   uint64   FreeVirtualMemory;
#   datetime InstallDate;
#   datetime LastBootUpTime;
#   datetime LocalDateTime;
#   uint32   MaxNumberOfProcesses;
#   uint64   MaxProcessMemorySize;
#   string   Name;
#   uint32   NumberOfLicensedUsers;
#   uint32   NumberOfProcesses;
#   uint32   NumberOfUsers;
#   uint16   OSType;
#   string   OtherTypeDescription;
#   uint64   SizeStoredInPagingFiles;
#   string   Status;
#   uint64   TotalSwapSpaceSize;
#   uint64   TotalVirtualMemorySize;
#   uint64   TotalVisibleMemorySize;
#   string   Version;
# };
class CIM_OperatingSystem(CIM_XmlMarshaller):
    def __init__(self):
        super(CIM_OperatingSystem, self).__init__()

        if not G_ReplayMode:
            self.OSType = sys.platform
            self.Name = os.name
            self.System = platform.system()
            self.Release = platform.release()
            self.Platform = platform.platform()

    cim_ontology_list = []


#
# class CIM_NetworkAdapter : CIM_LogicalDevice
# {
#   boolean  AutoSense;
#   uint16   Availability;
#   string   Caption;
#   uint32   ConfigManagerErrorCode;
#   boolean  ConfigManagerUserConfig;
#   string   CreationClassName;
#   string   Description;
#   string   DeviceID;
#   boolean  ErrorCleared;
#   string   ErrorDescription;
#   datetime InstallDate;
#   uint32   LastErrorCode;
#   uint64   MaxSpeed;
#   string   Name;
#   string   NetworkAddresses[];
#   string   PermanentAddress;
#   string   PNPDeviceID;
#   uint16   PowerManagementCapabilities[];
#   boolean  PowerManagementSupported;
#   uint64   Speed;
#   string   Status;
#   uint16   StatusInfo;
#   string   SystemCreationClassName;
#   string   SystemName;
# };
class CIM_NetworkAdapter(CIM_XmlMarshaller):
    def __init__(self, address):
        super(CIM_NetworkAdapter, self).__init__()
        self.Name = address
        self.PermanentAddress = address

    cim_ontology_list = ['Name']


# class CIM_Process : CIM_LogicalElement
# {
#  string   Caption;
#  string   CreationClassName;
#  datetime CreationDate;
#  string   CSCreationClassName;
#  string   CSName;
#  string   Description;
#  uint16   ExecutionState;
#  string   Handle;
#  datetime InstallDate;
#  uint64   KernelModeTime;
#  string   Name;
#  string   OSCreationClassName;
#  string   OSName;
#  uint32   Priority;
#  string   Status;
#  datetime TerminationDate;
#  uint64   UserModeTime;
#  uint64   WorkingSetSize;
# };
class CIM_Process(CIM_XmlMarshaller):
    def __init__(self, proc_id):
        """
        :param proc_id: Arguments of constructor. This is an int.
        """
        super(CIM_Process, self).__init__()

        # SOME MEMBERS MUST BE DISPLAYED AND FOLLOW CIM CONVENTION.
        # Key members must always be str.
        self.Handle = str(proc_id)
        self.m_parentProcess = None
        self.m_subProcesses = set()
        self.CreationDate = None
        self.TerminationDate = None

        # This contains all the files objects accessed by this process.
        # It is used when creating a DockerFile.
        # It is a set, so each file appears only once.
        self.m_ProcessFileAccesses = []

        # TODO: ADD AN ARRAY OF CIM_DataFile
        # AND THE ATTRIBUTES COULD CONTAIN THE DATA OF m_ProcessFileAccesses ???

        if not G_ReplayMode:
            # Maybe this cannot be accessed.
            if is_platform_linux:
                filnam_environ = "/proc/%d/environ" % int(self.Handle)
                try:
                    self.EnvironmentVariables = {}
                    with open(filnam_environ) as fd_env:
                        for one_pair in fd_env.readline().split('\0'):
                            env_key, colon, env_val = one_pair.partition('=')
                            if colon:
                                self.EnvironmentVariables[env_key] = env_val
                except:
                    pass

        if not G_ReplayMode and psutil:
            try:
                # FIXME: If rerunning a simulation, this does not make sense.
                # Same for CIM_DataFile when this is not the target machine.
                proc_obj = psutil.Process(proc_id)
            except:
                # Maybe this is replaying a former session and if so, the process exited.
                proc_obj = None
        else:
            proc_obj = None

        if proc_obj:
            try:
                self.Name = proc_obj.name()
                exec_fil_nam_raw = proc_obj.exe()
                exec_fil_nam = local_standardized_file_path(exec_fil_nam_raw)
                # The process id is not needed because the path is absolute and the process CIM object
                # should already be created. However, in the future it might reuse an existing context.
                objects_context = ObjectsContext(proc_id)
                exec_fil_obj = objects_context._class_model_to_object_path(CIM_DataFile, exec_fil_nam)

                # The process id is not needed because the path is absolute.
                # However, in the future it might reuse an existing context.
                # Also, the process must not be inserted twice.
                self.set_executable_path(exec_fil_obj)
                self.CommandLine = proc_obj.cmdline()
            except:
                self.Name = None

            try:
                # Maybe the process has exit.
                self.Username = proc_obj.username()
                self.Priority = proc_obj.nice()
            except:
                pass

            try:
                self.CurrentDirectory = local_standardized_file_path(proc_obj.cwd())
            except:
                # psutil.ZombieProcess process still exists but it's a zombie
                # Another possibility would be to use the parent process.
                self.CurrentDirectory = G_CurrentDirectory
        else:
            if proc_id > 0:
                self.Name = "pid=%s" % proc_id
            else:
                self.Name = ""
            # TODO: This could be deduced with calls to setuid().
            self.Username = ""
            # TODO: This can be partly deduced with calls to chdir() etc...
            # so it would not be necessary to install psutil.
            self.CurrentDirectory = G_CurrentDirectory
            self.Priority = 0

        # In the general case, it is not possible to get the parent process,
        # because it might replay a session. So, it can only rely on the successive function calls.
        # Therefore, the parent processes must be stored before the subprocesses.

    # TODO: Ontologies, i.e. list of clases and their attributes, should be stored in a RDF repository,
    # TODO: ... accessible from any application.
    # TODO: At the moment, these lists are stored in Python code and, when generating RDF data,
    # TODO: there is an extra pass of adding rdfs triples such as property and classes etc...
    # TODO: This pass is very simple and fast.
    # TODO: The reason for storing ontologies along Python code is for simplicity and ease of installing
    # TODO: ... new scripts and classes.
    # TODO: So the new representation requirements are:
    # TODO: - Must be granular, allowing the definition of new classes just by copying files.
    # TODO: - Must be very fast.
    # TODO: - Usable by any language.
    # TODO: - Implicitly creates a RDF server.
    # TODO: - The migration from the old to the new model can be done one at a time, withotu breaking change.
    # TODO: - This must reduce the extra pass of RDF data creation when exporting RDF data.
    #
    # TODO: Possible implementation:
    # TODO: - Each directory defining a class and its CGI script contains a RDF-XML file.
    # TODO: - This RDF file is loaded by scripts, at will.
    # TODO: - Python CGI scripts can transparently access the ontologies defined in these RDF files
    # TODO:   with a cache avoiding duplicates.
    # TODO: - Non-Python CGI scripts can directly load these files.
    # TODO: - Ideally, the RDF url is just a server of static files.


    cim_ontology_list = ['Handle']

    @classmethod
    def DisplaySummary(cls, fd_summary_file, cim_key_value_pairs):
        fd_summary_file.write("Processes:\n")
        list_CIM_Process = CIM_Process.m_G_map_cache_objects
        for obj_path, obj_instance in sorted(list_CIM_Process.items()):
            obj_instance.Summarize(fd_summary_file)
        fd_summary_file.write("\n")

    m_attributes_priorities = ["Handle", "Name", "CommandLine", "CreationDate", "TerminationDate", "Priority"]

    def XMLOneLevelSummary(self, strm, margin="    "):
        self.m_isVisited = True
        strm.write("%s<CIM_Process Handle='%s'>\n" % (margin, self.Handle))

        sub_margin = margin + "    "

        self.plain_to_XML(strm, sub_margin)

        FileAccess.serialize_list_to_XML(strm, self.m_ProcessFileAccesses, sub_margin, False)

        # The process are listed in the order of pids, stored in member Handle.
        for obj_instance in sorted(self.m_subProcesses, key=lambda one_proc: one_proc.Handle):
            obj_instance.XMLOneLevelSummary(strm, sub_margin)
        strm.write("%s</CIM_Process>\n" % margin)

    @staticmethod
    def top_process_from_proc(obj_instance):
        """This returns the top-level parent of a process."""
        while True:
            parent_proc = obj_instance.m_parentProcess
            if not parent_proc:
                return obj_instance
            obj_instance = parent_proc

    @staticmethod
    def get_top_processes():
        """This returns a list of top-level processes, which have no parents."""

        # This contains all subprocesses.
        set_sub_procs = set()
        for obj_path, obj_instance in CIM_Process.m_G_map_cache_objects.items():
            for one_sub in obj_instance.m_subProcesses:
                set_sub_procs.add(one_sub)

        lst_top_lvl = []
        for obj_path, obj_instance in CIM_Process.m_G_map_cache_objects.items():
            if obj_instance not in set_sub_procs:
                lst_top_lvl.append(obj_instance)
        return lst_top_lvl

    # When parsing the last system call, it sets the termination date for all processes.
    @staticmethod
    def global_termination_date(time_end):
        for obj_path, obj_instance in CIM_Process.m_G_map_cache_objects.items():
            if not obj_instance.TerminationDate:
                obj_instance.TerminationDate = time_end

    @classmethod
    def XMLSummary(cls, fd_summary_file, cim_key_value_pairs):
        """Find unvisited processes. It does not start from G_top_ProcessId
        because maybe it contains several trees, or subtrees were missed etc..."""
        for obj_path, obj_instance in sorted(CIM_Process.m_G_map_cache_objects.items()):
            try:
                obj_instance.m_isVisited
                continue
            except AttributeError:
                pass

            top_obj_proc = CIM_Process.top_process_from_proc(obj_instance)
            top_obj_proc.XMLOneLevelSummary(fd_summary_file)

    # In text mode, with no special formatting.
    def Summarize(self, strm):
        strm.write("Process id:%s\n" % self.Handle)
        try:
            if self.Executable:
                strm.write("    Executable:%s\n" % self.Executable)
        except AttributeError:
            pass
        if self.CreationDate:
            str_start = _timestamp_to_str(self.CreationDate)
            strm.write("    Start time:%s\n" % str_start)
        if self.TerminationDate:
            str_end = _timestamp_to_str(self.TerminationDate)
            strm.write("    End time:%s\n" % str_end)
        if self.m_parentProcess:
            strm.write("    Parent:%s\n" % self.m_parentProcess.Handle)

    def set_parent_process(self, objCIM_Process):
        # sys.stdout.write("set_parent_process proc=%s parent=%s\n" % ( self.Handle, objCIM_Process.Handle ) )
        if int(self.Handle) == int(objCIM_Process.Handle):
            raise Exception("Self-parent")
        self.m_parentProcess = objCIM_Process
        self.ParentProcessID = objCIM_Process.Handle
        objCIM_Process.m_subProcesses.add(self)

    def wait_process_end(self, time_stamp, objCIM_Process):
        # sys.stdout.write("wait_process_end: %s linking to %s\n" % (self.Handle,objCIM_Process.Handle))
        self.TerminationDate = time_stamp
        if not self.m_parentProcess:
            self.set_parent_process(objCIM_Process)
            # sys.stdout.write("wait_process_end: %s not linked to %s\n" % (self.Handle,objCIM_Process.Handle))
        elif self.m_parentProcess != objCIM_Process:
            # sys.stdout.write("wait_process_end: %s not %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass
        else:
            # sys.stdout.write("wait_process_end: %s already linked to %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass

    def set_executable_path(self, objCIM_DataFile):
        assert isinstance(objCIM_DataFile, CIM_DataFile)
        self.Executable = objCIM_DataFile.Name
        self.m_ExecutableObject = objCIM_DataFile

    def set_command_line(self, lst_cmd_line):
        # TypeError: sequence item 7: expected string, dict found
        if lst_cmd_line:
            self.CommandLine = " ".join(map(str, lst_cmd_line))
            # The command line as a list is needed by Dockerfile.
            self.m_commandList = lst_cmd_line

    def get_command_line(self):
        try:
            if self.CommandLine:
                return self.CommandLine
        except AttributeError:
            pass

        try:
            command_line = self.Executable
        except AttributeError:
            command_line = ""
        return command_line

    def get_command_list(self):
        try:
            if self.m_commandList:
                return self.m_commandList
        except AttributeError:
            pass

        try:
            command_list = [self.Executable]
        except AttributeError:
            command_list = []
        return command_list

    def set_process_current_directory(self, curr_dir_object):
        """Some system calls are relative to the current directory.
        Therefore, this traces current dir changes due to system calls."""
        self.CurrentDirectory = curr_dir_object.Name
        assert isinstance(self.CurrentDirectory, str)

    def get_process_current_directory(self):
        assert isinstance(self.CurrentDirectory, str)
        return self.CurrentDirectory

    def get_file_access(self, objCIM_DataFile, open_letter):
        """
        This returns an object indexed by the file name and the process id.
        A file might have been opened several times by the same process.
        Therefore, once a file has been closed, the associated file access cannot be returned again.
        """
        one_file_access = FileAccess.lookup_file_access(self, objCIM_DataFile, open_letter)
        return one_file_access


# Other tools to consider:
# dtrace and blktrac and valgrind
# http://www.brendangregg.com/ebpf.html

# class CIM_LogicalFile : CIM_LogicalElement
# {
#   string   Caption;
#   string   Description;
#   datetime InstallDate;
#   string   Status;
#   uint32   AccessMask;
#   boolean  Archive;
#   boolean  Compressed;
#   string   CompressionMethod;
#   string   CreationClassName;
#   datetime CreationDate;
#   string   CSCreationClassName;
#   string   CSName;
#   string   Drive;
#   string   EightDotThreeFileName;
#   boolean  Encrypted;
#   string   EncryptionMethod;
#   string   Name;
#   string   Extension;
#   string   FileName;
#   uint64   FileSize;
#   string   FileType;
#   string   FSCreationClassName;
#   string   FSName;
#   boolean  Hidden;
#   uint64   InUseCount;
#   datetime LastAccessed;
#   datetime LastModified;
#   string   Path;
#   boolean  Readable;
#   boolean  System;
#   boolean  Writeable;
# };
class CIM_LogicalFile(CIM_XmlMarshaller):

    # These regular expressions to extract port numbers of TCP sockets.
    # They are prefixed with "m_" because of _is_CIM.
    # 'TCP:[54.36.162.150:37415->82.45.12.63:63708]'
    m_regex_tcp_v4_port = re.compile(r"TCP:\[.*->(.*)\]")
    # 'TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]'
    m_regex_tcp_v6_port = re.compile(r"TCPv6:\[.*->(.*)\]")

    def __init__(self, path_name):
        super(CIM_LogicalFile, self).__init__()

        # https://msdn.microsoft.com/en-us/library/aa387236(v=vs.85).aspx
        # The Name property is a string representing the inherited name
        # that serves as a key of a logical file instance within a file system.
        # Full path names should be provided.

        # TODO: When the name contains "<" or ">" it cannot be properly displayed in SVG.
        # TODO: Also, names like "UNIX:" or "TCP:" should be processed a special way.
        self.Name = path_name
        # File name without the file name extension. Example: "MyDataFile"
        try:
            bas_na = os.path.basename(path_name)
            # There might be several dots, or none.
            self.FileName = bas_na.split(".")[0]
        except:
            pass
        self.Category = _pathname_to_category(path_name)

        self.m_DataFileFileAccesses = []

        # Some information are meaningless because they vary between executions.
        if G_SameMachine:
            try:
                obj_stat = os.stat(path_name)
                self.FileSize = obj_stat.st_size
                self.FileMode = obj_stat.st_mode
                self.Inode = obj_stat.st_ino
                self.DeviceId = obj_stat.st_dev
                self.HardLinksNumber = obj_stat.st_nlink
                self.OwnerUserId = obj_stat.st_uid
                self.OwnerGroupId = obj_stat.st_gid
                self.AccessTime = _time_t_to_datetime(obj_stat.st_atime)
                self.ModifyTime = _time_t_to_datetime(obj_stat.st_mtime)
                self.CreationTime = _time_t_to_datetime(obj_stat.st_ctime)

                # This is on Windows only.
                # self.UserDefinedFlags = obj_stat.st_flags
                # self.FileCreator = obj_stat.st_creator
                # self.FileType = obj_stat.st_type
                try:
                    # This does not exist on Windows.
                    self.DeviceType = obj_stat.st_rdev
                except AttributeError:
                    pass
            except:
                pass

        # If this is a connected socket:
        # 'TCP:[54.36.162.150:37415->82.45.12.63:63708]'
        mtch_sock = self.m_regex_tcp_v4_port.match(path_name)
        if mtch_sock:
            self.SetAddrPort(mtch_sock.group(1))
        else:
            # 'TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]'
            mtch_sock = self.m_regex_tcp_v6_port.match(path_name)
            if mtch_sock:
                self.SetAddrPort(mtch_sock.group(1))

    cim_ontology_list = ['Name']



# class CIM_DataFile : CIM_LogicalFile
# {
# string   Caption;
# string   Description;
# datetime InstallDate;
# string   Status;
# uint32   AccessMask;
# boolean  Archive;
# boolean  Compressed;
# string   CompressionMethod;
# string   CreationClassName;
# datetime CreationDate;
# string   CSCreationClassName;
# string   CSName;
# string   Drive;
# string   EightDotThreeFileName;
# boolean  Encrypted;
# string   EncryptionMethod;
# string   Name;
# string   Extension;
# string   FileName;
# uint64   FileSize;
# string   FileType;
# string   FSCreationClassName;
# string   FSName;
# boolean  Hidden;
# uint64   InUseCount;
# datetime LastAccessed;
# datetime LastModified;
# string   Path;
# boolean  Readable;
# boolean  System;
# boolean  Writeable;
# string   Manufacturer;
# string   Version;
# };
class CIM_DataFile(CIM_LogicalFile):
    def __init__(self, path_name):
        super(CIM_DataFile, self).__init__(path_name)

    # This creates a map containing all detected files. This map is indexed
    # by an informal file category: DLL, data file etc...
    @staticmethod
    def SplitFilesByCategory():
        map_files = CIM_DataFile.m_G_map_cache_objects.items()

        # TODO: Find a way to define the presentation as a parameter.
        # Maybe we can use the list of keys: Just mentioning a property
        # means that a sub-level must be displayed.
        map_of_files_map = {rgx_tuple[0]: {} for rgx_tuple in G_lstFilters}

        # obj_path = 'CIM_DataFile.Name="/usr/lib64/libcap.so.2.24"'
        for obj_path, obj_instance in map_files:
            map_of_files_map[obj_instance.Category][obj_path] = obj_instance
        return map_of_files_map

    @classmethod
    def DisplaySummary(cls, fd_summary_file, cim_key_value_pairs):
        fd_summary_file.write("Files:\n")
        map_of_files_map = CIM_DataFile.SplitFilesByCategory()

        try:
            filter_cats = cim_key_value_pairs["Category"]
        except KeyError:
            filter_cats = None

        for category_files, map_files_sub in sorted(map_of_files_map.items()):
            fd_summary_file.write("\n** %s\n" % category_files)
            if filter_cats and category_files not in filter_cats:
                continue
            for obj_path, obj_instance in sorted(map_files_sub.items()):
                obj_instance.Summarize(fd_summary_file)
        fd_summary_file.write("\n")

    m_attributes_priorities = ["Name", "Category", "SocketAddress"]

    def XMLDisplay(self, strm):
        margin = "        "
        strm.write("%s<CIM_DataFile Name='%s'>\n" % (margin, self.Name))

        sub_margin = margin + "    "

        self.plain_to_XML(strm, sub_margin)

        FileAccess.serialize_list_to_XML(strm, self.m_DataFileFileAccesses, sub_margin, True)

        strm.write("%s</CIM_DataFile>\n" % margin)

    @staticmethod
    def XMLCategorySummary(fd_summary_file, map_files_sub):
        for obj_path, obj_instance in sorted(map_files_sub.items()):
            obj_instance.XMLDisplay(fd_summary_file)

    @classmethod
    def XMLSummary(cls, fd_summary_file, cim_key_value_pairs):
        """Top-level informations are categories of CIM_DataFile which are not technical
        but the regex-based filtering."""
        map_of_files_map = CIM_DataFile.SplitFilesByCategory()

        try:
            filter_cats = cim_key_value_pairs["Category"]
        except KeyError:
            filter_cats = None

        for category_files, map_files_sub in sorted(map_of_files_map.items()):
            if len(map_files_sub) == 0:
                # No need to write a category name if it is empty.
                continue

            fd_summary_file.write("    <FilesCategory category='%s'>\n" % category_files)
            if filter_cats and category_files not in filter_cats:
                continue
            CIM_DataFile.XMLCategorySummary(fd_summary_file, map_files_sub)
            fd_summary_file.write("    </FilesCategory>\n")

    def Summarize(self, strm):
        try:
            # By default, this attribute is not set.
            if self.IsExecuted:
                return
        except AttributeError:
            pass
        strm.write("Path:%s\n" % self.Name)

        for fil_acc in self.m_DataFileFileAccesses:
            if fil_acc.OpenTime:
                str_open = _timestamp_to_str(fil_acc.OpenTime)
                strm.write("  Open:%s\n" % str_open)

                try:
                    strm.write("  Open times:%d\n" % fil_acc.NumOpen)
                except AttributeError:
                    pass

            if fil_acc.CloseTime:
                str_close = _timestamp_to_str(fil_acc.CloseTime)
                strm.write("  Close:%s\n" % str_close)

        # Only if this is a socket.
        # The original socket parameters might have been passed as a dict like:
        # "connect(6<UNIX:[587259]>, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110)"
        # But it might have been truncated like:
        # "['st_mode=S_IFREG|0644', 'st_size=121043', '...']"
        # So we are only sure that it is an array.
        try:
            for sa_key_value in self.SocketAddress:
                strm.write("    %s\n" % sa_key_value)
        except AttributeError:
            pass

    def set_is_executed(self):
        self.IsExecuted = True

    # The input could be IPV4 or IPV6:
    # '82.45.12.63:63708]'
    # '::ffff:82.45.12.63:63703]'
    def SetAddrPort(self, path_ip):
        ix_eq = path_ip.rfind(":")
        if ix_eq < 0:
            self.Destination = path_ip
        else:
            self.Port = path_ip[ix_eq + 1:]
            addr_ip = path_ip[:ix_eq]
            try:
                self.Destination = socket.gethostbyaddr(addr_ip)[0]
            except:
                self.Destination = addr_ip

    @staticmethod
    def GetExposedPorts():
        """this is is the list of all ports numbers whihc have to be open."""

        map_files = CIM_DataFile.m_G_map_cache_objects.items()
        set_ports = set()
        for obj_path, obj_instance in map_files:
            try:
                set_ports.add(obj_instance.Port)
            except AttributeError:
                pass
        return set_ports

    m_non_file_prefixes = (
        "pipe:[", "TCP:", "TCPv6:[", "anon_inode:[", "NETLINK:[", "UDP:[", "UNIX:[", "UDPv6:",
        "/dev/", "/proc/")

    @staticmethod
    def is_plain_file(file_basename):
        assert isinstance(file_basename, str)
        return not file_basename.startswith(CIM_DataFile.m_non_file_prefixes)


# class CIM_Directory : CIM_LogicalFile
# {
#   uint32   AccessMask;
#   boolean  Archive;
#   string   Caption;
#   boolean  Compressed;
#   string   CompressionMethod;
#   string   CreationClassName;
#   datetime CreationDate;
#   string   CSCreationClassName;
#   string   CSName;
#   string   Description;
#   string   Drive;
#   string   EightDotThreeFileName;
#   boolean  Encrypted;
#   string   EncryptionMethod;
#   string   Extension;
#   string   FileName;
#   uint64   FileSize;
#   string   FileType;
#   string   FSCreationClassName;
#   string   FSName;
#   boolean  Hidden;
#   datetime InstallDate;
#   uint64   InUseCount;
#   datetime LastAccessed;
#   datetime LastModified;
#   string   Name;
#   string   Path;
#   boolean  Readable;
#   string   Status;
#   boolean  System;
#   boolean  Writeable;
# };
class CIM_Directory(CIM_LogicalFile):
    def __init__(self, path_name):
        super(CIM_Directory, self).__init__(path_name)


# This must appear AFTER the declaration of classes.
_class_name_to_subclass = {cls.__name__: cls for cls in leaf_derived_classes(CIM_XmlMarshaller)}


def to_real_absolute_path(directory_path, file_basename):
    """os.path.abspath removes things like . and .. from the path
    giving a full path from the root of the directory tree to the named file (or symlink)"""

    assert isinstance(directory_path, str)
    assert isinstance(file_basename, str)

    if file_basename in ["stdout", "stdin", "stderr"]:
        return file_basename

    if not CIM_DataFile.is_plain_file(file_basename):
        return file_basename

    if file_basename.startswith("UnknownFileDescr"):
        return file_basename

    join_path = os.path.join(directory_path, file_basename)

    norm_path = local_standardized_file_path(join_path)
    return norm_path

################################################################################


# Read from a real process or from the log file name when replaying a session.
# It is conceptually part of an ObjectsContext.
G_topProcessId = None

################################################################################


class ObjectsContext:
    """This helps creating CIM objects based on their class name and key-value pairs
    defined from the ontology. The role of this context object is to contain
    everything which is needed to create a CIM object without ambiguity.
    The typical example is, when creating a CIM_DataFile, only the relative path name
    might be available. So, the process current work directory is needed,
    and given by this context."""

    # TODO: Store these objects in a dictionary instead of re-creating them.
    def __init__(self, process_id=None):
        self._process_id = process_id

    def attributes_to_cim_object(self, cim_class_name, **cim_attributes_dict):
        """This is used by Windows pydbg callback, when an object creation is detected.
        It calls this method with a class name, and a dict of key-values.
        It is up to this generic routine to fill the internal data
        which are used to generate execution reports.
        The caller must be aware of correct class names and their attributes."""
        if cim_class_name == "CIM_Process":
            cim_key_handle = cim_attributes_dict['Handle']
            return self.ToObjectPath_CIM_Process(cim_key_handle)
        if cim_class_name == "CIM_DataFile":
            file_pathname = cim_attributes_dict['Name']
            return self.ToObjectPath_CIM_DataFile(file_pathname)

        # In the general case, reorder the arguments.
        cim_object_datafile = CIM_XmlMarshaller.create_instance_from_class_name(cim_class_name, **cim_attributes_dict)
        return cim_object_datafile

    def ToObjectPath_CIM_Process(self, process_id):
        """This returns the newly-created of cached object associated to a pid.
        Thus function needs the parent process id, because it cannot be retrieved when replaying
        a session, and it might be difficult even when tracing a real process.
        Because the tracer gives the parent id when creating a subprocess,
        it is simpler to use it in the context of the parent process.
        """

        returned_object = self._class_model_to_object_path(CIM_Process, process_id)

        if process_id != self._process_id:
            # Now the subprocess must be connected to its parent process.
            # Maybe the subprocess was created but not "connected" to its parent process,
            # because this relationship is detected after the return of the process creation in the parent process.
            # Therefore, this checks that the parent process is specified.

            # Dictionary of all processes, indexed by the tuple of their key-value
            map_procs = CIM_Process.m_G_map_cache_objects

            # The key is a tuple of the arguments in the order of the ontology.
            parent_proc_obj = map_procs[(self._process_id,)]

            returned_object.set_parent_process(parent_proc_obj)
        return returned_object

    def ToObjectPath_CIM_DataFile(self, path_name):
        """It might be a Linux socket or an IP socket.
        The pid can be added so we know which process accesses this file."""

        # TODO: All pathnames should be "str", to avoid conversions.
        assert isinstance(path_name, str)

        # TODO: If this is an absolute path name, the current directory of the processis not needed.
        if self._process_id:
            # Maybe this is a relative file, and to make it absolute, the process is needed,
            # because it gives the process current working directory.
            obj_process = self.ToObjectPath_CIM_Process(self._process_id)
            dir_path = obj_process.get_process_current_directory()
        else:
            # At least it will suppress ".." etc...
            dir_path = ""

        # On Windows, fix capitals in file name. On Linux, dereference symbolic links.
        path_name = to_real_absolute_path(dir_path, path_name)

        obj_data_file = self._class_model_to_object_path(CIM_DataFile, path_name)
        return obj_data_file

    def _class_model_to_object_path(self, class_model, *ctor_args):
        """This receives a class name and a list of key-value pairs.
        It returns the object, possibly from a cache shared by all processes because it is in the class."""
        map_objs = class_model.m_G_map_cache_objects

        # Here, this tuple in the order of the ontology is a key in a per-class dictionary.
        try:
            the_obj = map_objs[ctor_args]
        except KeyError:
            the_obj = class_model(*ctor_args)
            map_objs[ctor_args] = the_obj
        return the_obj

################################################################################


def generate_dockerfile(docker_filename):
    """
    This generates a dockerfile reproducing the sessions traced with dockit.
    """
    fd_docker_file = open(docker_filename, "w")

    def _write_environment_variables():
        """This writes in the DockerFile, the environment variables accessed
        by processes. For the moment, all env vars are mixed together,
        which is inexact, strictly speaking."""

        # Always written in the same order so the test can be reproduced.
        for env_nam in sorted(G_EnvironmentVariables):
            env_val = G_EnvironmentVariables[env_nam]
            if env_val == "":
                # Error response from daemon: ENV must have two arguments
                env_val = '""'
            fd_docker_file.write("ENV %s %s\n" % (env_nam, env_val))

        fd_docker_file.write("\n")

    def _write_process_tree():
        """Only for documentation purpose"""

        def write_one_process_sub_tree(obj_proc, depth):
            command_line = obj_proc.get_command_line()
            if not command_line:
                command_line = "*Unknown-command*"
            fd_docker_file.write("# %s -> %s : %s %s\n" % (
                _timestamp_to_str(obj_proc.CreationDate),
                _timestamp_to_str(obj_proc.TerminationDate),
                "    " * depth,
                command_line)
            )

            for sub_proc in sorted(obj_proc.m_subProcesses, key=lambda x: x.Handle):
                write_one_process_sub_tree(sub_proc, depth + 1)

        fd_docker_file.write("# Processes tree\n")

        procs_top_level = CIM_Process.get_top_processes()
        for one_proc in sorted(procs_top_level, key=lambda x: x.Handle):
            write_one_process_sub_tree(one_proc, 1)
        fd_docker_file.write("\n")

    docker_directory = os.path.dirname(docker_filename)

    fd_docker_file.write("FROM docker.io/fedora\n")
    fd_docker_file.write("\n")

    fd_docker_file.write("MAINTAINER contact@primhillcomputers.com\n")
    fd_docker_file.write("\n")

    _generate_docker_process_dependencies(docker_directory, fd_docker_file)

    # Top-level processes, which starts the other ones.
    # Probably there should be one only, but this is not a constraint.
    procs_top_level = CIM_Process.get_top_processes()
    for one_proc in procs_top_level:
        # TODO: Possibly add the command "VOLUME" ?
        curr_dir = one_proc.get_process_current_directory()
        fd_docker_file.write("WORKDIR %s\n" % curr_dir)

        command_list = one_proc.get_command_list()
        if command_list:
            # If the string length read by ltrace or strace is too short,
            # some arguments are truncated: 'CMD ["python TestProgs/big_mysql_..."]'

            # There should be one CMD command only !
            str_cmd = ",".join('"%s"' % wrd for wrd in command_list)

            fd_docker_file.write("CMD [ %s ]\n" % str_cmd)
    fd_docker_file.write("\n")

    ports_list = CIM_DataFile.GetExposedPorts()
    if ports_list:
        fd_docker_file.write("# Port numbers:\n")
        for one_port in ports_list:
            try:
                txt_port = socket.getservbyport(int(one_port))
                fd_docker_file.write("# Service: %s\n" % txt_port)
            except:
                fd_docker_file.write("# Unknown service number: %s\n" % one_port)
            fd_docker_file.write("EXPOSE %s\n" % one_port)
        fd_docker_file.write("\n")

    _write_environment_variables()

    _write_process_tree()

    # More examples here:
    # https://github.com/kstaken/dockerfile-examples/blob/master/couchdb/Dockerfile

    fd_docker_file.close()
    return


def generate_makefile(output_makefile):
    """
    This generates a makefile with all input and output file dependencies,
    and the command which generates them.
    In this kind of context, a file should be created only once, and by one process only.
    This does not work if a file is rewritten.

    This is targeted at makefiles and C/C++ files for the moment.
    Therefore, there are hard-coded file extensions etc...
    """

    def _is_standard_lib_file(file_name):
        """Files from the standard library do not need to be included in makefiles. """
        return file_name.startswith(("/usr/", "/lib64/", "/etc/"))

    out_fd = open(output_makefile, "w")
    out_fd.write("# Generated makefile: %s\n" % str(G_Today))
    out_fd.write("# Working directory:%s\n" % G_CurrentDirectory)

    # TODO: This does not work if a file is rewritten.

    cached_processes = CIM_Process.m_G_map_cache_objects
    for obj_path in sorted(cached_processes.keys()):
        one_proc = cached_processes[obj_path]

        # This creates two input and output files of each process.
        input_files = set()
        output_files = set()

        for fil_acc in one_proc.m_ProcessFileAccesses:
            one_file = fil_acc.m_objectCIM_DataFile

            # Special files such as "/dev/" or "/proc/" are not taken into consideration.
            if not CIM_DataFile.is_plain_file(one_file.Name):
                continue

            # Standard libraries and header files are not taken into consideration.
            if _is_standard_lib_file(one_file.Name):
                continue

            # TODO: If a file is open rw, but without write access, what to do ?
            if fil_acc.m_openFlag == "R":
                input_files.add(one_file)
            else:
                output_files.add(one_file)

        if not input_files:
            continue

        input_files = sorted(input_files, key=lambda obj_fil: obj_fil.Name)

        try:
            command_line = one_proc.get_command_line()
        except AttributeError:
            command_line = "Unknown command line"
        curr_dir = one_proc.get_process_current_directory()

        # TODO: What of a file is written by several process ?
        for one_out_file in sorted(output_files, key=lambda obj_fil: obj_fil.Name):
            # TODO: Write the environment variables of the process.

            # TODO: This filter is hard-coded but not a problem now.
            depends_files = " ".join(
                in_fil.Name
                for in_fil in input_files
                if not in_fil.Name.startswith(("/usr/", "/lib64/", "/dev/", "/proc/"))
            )
            out_fd.write("%s: %s\n" % (one_out_file.Name, depends_files))

            # TODO: If there are several output files, it is a waste to run the same command several times.
            out_fd.write("\t# Directory: %s\n" % curr_dir)
            out_fd.write("\t%s\n" % command_line)
            out_fd.write("\n")

    out_fd.close()
    print("Created makefile:", output_makefile)


# Environment variables actually access by processes.
# Used to generate a Dockerfile.
# As read from the strace or ltrace calls to getenv()
G_EnvironmentVariables = None


def init_global_objects(the_hostname, the_ip_address):
    global G_httpClient
    global G_EnvironmentVariables


    def reset_subclasses_instances(the_class):
        # This is similar to leaf_derived_classes, but all subclasses are read.
        for the_subclass in the_class.__subclasses__():
            try:
                del the_subclass.m_G_map_cache_objects
            except AttributeError:
                pass
            the_subclass.m_G_map_cache_objects = {}
            reset_subclasses_instances(the_subclass)

    reset_subclasses_instances(CIM_XmlMarshaller)

    # This object is used to send triples to a Survol server.
    # It is also used to store the triples in a RDF file, which is created by the destructor.
    G_httpClient = http_triples_client_factory()

    # As read from the strace or ltrace calls to getenv()
    G_EnvironmentVariables = {}

    # Not os.getpid() because it might be a replay.
    objects_context = ObjectsContext(G_topProcessId)

    # This could be the current host name, or read from a file for a replay.
    objects_context._class_model_to_object_path(CIM_ComputerSystem, the_hostname)
    objects_context._class_model_to_object_path(CIM_OperatingSystem)
    # This could be the current host name, or read from a file for a replay.
    objects_context._class_model_to_object_path(CIM_NetworkAdapter, the_ip_address)


def exit_global_objects():
    # It is also used to store the triples in a RDF file, which is created by the destructor.
    global G_httpClient
    # Flushes the data to a file or possibly a Survol agent.
    G_httpClient.http_client_shutdown()


def _lambda_regex_match(regex_file_path):
    compiled_regex = re.compile(regex_file_path)
    return lambda file_path: compiled_regex.match(file_path)


def _lambda_starts_with(path_prefix_tuple):
    return lambda file_path: file_path.startswith(path_prefix_tuple)


# This is not a map, it is not sorted.
# It contains objects for classifying file names in categories:
# Shared libraries, source files, scripts, Linux pipes etc...
# They must be processed in this order because there is a priority.
G_lstFilters = [
    ("Shared libraries", [
        _lambda_regex_match(r"^/usr/lib[^/]*/.*\.so"),
        _lambda_regex_match(r"^/usr/lib[^/]*/.*\.so\..*"),
        _lambda_regex_match(r"^/var/lib[^/]*/.*\.so"),
        _lambda_regex_match(r"^/lib/.*\.so"),
        _lambda_regex_match(r"^/lib64/.*\.so"),
    ]),
    ("System config files", [
        _lambda_starts_with((
            "/etc/",
            "/usr/share/fonts/",
            "/usr/share/fontconfig/",
            "/usr/share/locale/",
            "/usr/share/zoneinfo/")),
    ]),
    ("Other libraries", [
        _lambda_starts_with((
            "/usr/share/",
            "/usr/lib/",
            "/usr/lib64/",
            "/var/lib/",
            "/var/lib64/")),
    ]),
    ("System executables", [
        _lambda_starts_with((
            "/bin/",
            "/usr/bin/",
            "/usr/bin64/")),
]),
    ("Kernel file systems", [
        _lambda_starts_with((
            "/proc",
            "/run")),
    ]),
    ("Temporary files", [
        _lambda_starts_with((
            "/tmp/",
            "/var/log/",
            "/var/cache/")),
    ]),
    ("Pipes and terminals", [
        _lambda_starts_with((
            "/sys",
            "/dev",
            "pipe:",
            "socket:",
            "UNIX:",
            "NETLINK:")),
    ]),
    # TCP:[54.36.162.150:41039->82.45.12.63:63711]
    ("Connected TCP sockets", [
        _lambda_regex_match(r"^TCP:\[.*->.*\]"),
        _lambda_regex_match(r"^TCPv6:\[.*->.*\]"),
    ]),
    ("Other TCP/IP sockets", [
        _lambda_starts_with((
            "TCP:",
            "TCPv6:",
            "UDP:",
            "UDPv6:")),
    ]),
    ("Others", []),
]


def _pathname_to_category(path_name):
    """This matches the path name against the set of regular expressions
    defining broad categories of files: Sockets, libraries, temporary files...
    These categories are not technical but based on application best practices,
    rules of thumbs etc..."""
    for category_key, lambda_list in G_lstFilters:
        for one_lambda in lambda_list:
            # If the file matches a regular expression, then it is classified in this category.
            if one_lambda(path_name):
                return category_key
    return "Others"

################################################################################


# See https://github.com/nbeaver/pip_file_lookup
_python_cache = {}


# TODO: Not used yet !!
def PathToPythonModuleOneFileMakeCache(path):
    global _python_cache

    try:
        import lib_python
        pip_installed_distributions = lib_python.PipGetInstalledDistributions()
        if pip_installed_distributions == None:
            return
    except ImportError:
        return

    for dist in pip_installed_distributions:
        # RECORDs should be part of .dist-info metadatas
        if dist.has_metadata('RECORD'):
            lines = dist.get_metadata_lines('RECORD')
            paths = [l.split(',')[0] for l in lines]
            dist_directory = dist.location
        # Otherwise use pip's log for .egg-info's
        elif dist.has_metadata('installed-files.txt'):
            paths = dist.get_metadata_lines('installed-files.txt')
            dist_directory = dist.egg_info
        else:
            dist_directory = None

        if dist_directory:
            for p in paths:
                normed_path = os.path.normpath( os.path.join(dist_directory, p) )
                try:
                    _python_cache[normed_path].append(dist)
                except KeyError:
                    _python_cache[normed_path] = [dist]


def _path_to_python_module_one_file(path):
    try:
        return _python_cache[path]
    except KeyError:
        return []


def _files_to_python_modules(unpackaged_data_files):
    """
    This takes as input a list of files, some of them installed by Python modules,
    and others having nothing to do with Python. It returns two data structures:
    - The set of unique Python modules, some files come from.
    - The remaining list of files, not coming from any Python module.
    This allow to reproduce an environment.
    """
    set_python_modules = set()
    unknown_data_files = []

    for one_fil_obj in unpackaged_data_files:
        lst_modules = _path_to_python_module_one_file(one_fil_obj.Name)
        # TODO: Maybe just take one module ?
        # sys.stdout.write("path=%s mods=%s\n"%(one_fil_obj.Name, str(list(lst_modules))))
        added_one = False
        for one_mod in lst_modules:
            set_python_modules.add(one_mod)
            added_one = True
        if not added_one:
            unknown_data_files.append(one_fil_obj)

    return set_python_modules, unknown_data_files


def _generate_docker_process_dependencies(docker_directory, fd_docker_file):
    """
    Display the dependencies of processes.
    They might need the installation of libraries. modules etc...
    Sometimes these dependencies are the same.
    The type of process can be: "Binary", "Python", "Perl" etc...
    and for each of these it receive a list of strings, each of them models
    a dependency: a RPM package, a Python module etc...
    Sometimes, they can be be similar and will therefore be loaded once.
    The type of process contains some specific code which can generate
    the Dockerfile commands for handling these dependencies.
    """

    # TODO: Do not duplicate Python modules installation.
    def install_pip_module(fd_docker_file, name_py_module):
        fd_docker_file.write("RUN pip --disable-pip-version-check install %s\n" % name_py_module)

    def install_linux_package(fd_docker_file, package_name):
        # packageName = "mariadb-libs-10.1.30-2.fc26.x86_64"
        # RUN yum install mariadb-libs
        if package_name in install_linux_package.InstalledPackages:
            pck_short = install_linux_package.InstalledPackages[package_name]
            fd_docker_file.write("# Already installed %s -> %s\n" % (pck_short, package_name))
            return

        # TODO: Maybe there are several versions of the same package.
        mtch = re.search(r'(.*)-(.*)-(.*?)\.(.*)', package_name)
        if mtch:
            pck_short, version, release, the_platform = mtch.groups()
        else:
            pck_short = package_name

        install_linux_package.InstalledPackages[package_name] = pck_short

        # Step 4/7 : RUN yum -y install coreutils # coreutils-8.27-5.fc26.x86_64
        # Problem: problem with installed package coreutils-single-8.29-5.fc28.x86_64
        # - package coreutils-8.29-5.fc28.x86_64 conflicts with coreutils-single provided by coreutils-single-8.29-5.fc28.x86_64
        # (try to add '--allowerasing' to command line to replace conflicting packages or '--skip-broken' to skip uninstallable packages)

        # For the moment, this is simpler.
        if pck_short in ['coreutils']:
            fd_docker_file.write("# Potential conflict with %s , %s\n" % (pck_short, package_name))
        else:
            fd_docker_file.write("RUN yum -y install %s # %s\n" % (pck_short, package_name))

    # Each package is installed only once.
    install_linux_package.InstalledPackages = dict()

    # FIXME: We could copy an entire directory tree. When ?
    def add_to_docker_dir(path_name, fil_comment=0):
        # Maybe the input file does not exist.
        if not os.path.exists(path_name):
            fd_docker_file.write("# Origin file does not exist:%s\n" % path_name)
            return

        # No need to copy directories.
        if os.path.isdir(path_name):
            return

        org_dir = os.path.dirname(path_name)
        dst_dir = docker_directory + "/" + org_dir

        if not os.path.exists(dst_dir):
            os.makedirs(dst_dir)
        dst_path = docker_directory + "/" + path_name
        try:
            # Copy the file at the right place, so "docker build" can find it.
            shutil.copy(path_name, dst_path)
        except IOError:
            logging.error("Failed copy %s to %s" % (path_name, dst_path))
            # Maybe the file is not there because this is in replay mode,
            # rerunning a session form the log file. This is not a problem.
            fd_docker_file.write("# Cannot add non-existent file:%s\n" % path_name)
            return

        if fil_comment:
            fd_docker_file.write("# %s\n" % fil_comment)

        fd_docker_file.write("ADD %s %s\n" % (path_name, path_name))

    # Code dependencies and data files dependencies are different.

    # All versions mixed together which is realistic most of times.
    class Dependency(object):
        def __init__(self):
            self.m_accessedCodeFiles = set()

        def add_file_dependency(self, path_name):
            self.m_accessedCodeFiles.add(path_name)

    class DependencyPython(Dependency):
        DependencyName = "Python scripts"

        def __init__(self):
            super(DependencyPython, self).__init__()

        @staticmethod
        def is_dependency_of(objInstance):
            try:
                # Detection with strace:
                # execve("/usr/bin/python", ["python", "TestProgs/mineit_mys"...], [/* 22 vars */]) = 0
                # Detection with ltrace:
                # __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
                return objInstance.Executable.find("/python") >= 0 or objInstance.Executable.startswith("python")
            except AttributeError:
                # We do not know the executable, or it is a thread.
                return False

        @staticmethod
        def is_executable_file(obj_data_file):
            return obj_data_file.Name.endswith((".py", ".pyc", ".pyd"))

        def generate_docker_dependencies(self, fd_docker_file):
            packages_to_install = set()

            for obj_data_file in self.m_accessedCodeFiles:
                fil_nam = obj_data_file.Name
                if fil_nam.find("packages") >= 0:
                    # Now this truncates the file name to extract the Python package name.
                    split_fil = fil_nam.split("/")
                    try:
                        ix_pack = split_fil.index("site-packages")
                    except ValueError:
                        try:
                            ix_pack = split_fil.index("dist-packages")
                        except ValueError:
                            ix_pack = -1
                            pass

                    if (ix_pack >= 0) and (ix_pack < len(split_fil) - 1):
                        pck_nam = split_fil[ix_pack + 1]
                        # if not pck_nam.endswith(".py") and not pck_nam.endswith(".pyc"):
                        if not pck_nam.endswith((".py", ".pyc")):
                            packages_to_install.add(split_fil[ix_pack + 1])
                elif not fil_nam.startswith("/usr/"):
                    # Do not copy files from the standard installation and always available, such as:
                    # "ADD /usr/lib64/python2.7/cgitb.py /"
                    add_to_docker_dir(fil_nam, "Python dependency")
                else:
                    pass

            if packages_to_install or self.m_accessedCodeFiles:
                install_linux_package(fd_docker_file, "python")

            for one_pckg_nam in sorted(packages_to_install):
                # TODO: Do not duplicate Python modules installation.
                install_pip_module(fd_docker_file, one_pckg_nam)

    class DependencyPerl(Dependency):
        DependencyName = "Perl scripts"

        def __init__(self):
            super(DependencyPerl, self).__init__()

        @staticmethod
        def is_dependency_of(obj_instance):
            try:
                return obj_instance.Executable.find("/perl") >= 0
            except AttributeError:
                # We do not know the executable, or it is a thread.
                return False

        @staticmethod
        def is_executable_file(obj_data_file):
            return obj_data_file.Name.endswith(".pl")

        def generate_docker_dependencies(self, fd_docker_file):
            for obj_data_file in self.m_accessedCodeFiles:
                fil_nam = obj_data_file.Name
                fd_docker_file.write("RUN cpanm %s\n" % fil_nam)
            pass

    class DependencyBinary(Dependency):
        DependencyName = "Binary programs"

        def __init__(self):
            super(DependencyBinary, self).__init__()

        @staticmethod
        def is_dependency_of(obj_instance):
            # Always true because tested at the end as a default.
            # The executable should at least be an executable file.
            return True

        @staticmethod
        def is_executable_file(obj_data_file):
            return obj_data_file.Name.find(".so") > 0

        def generate_docker_dependencies(self, fd_docker_file):
            # __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
            #    return obj_instance.Executable.find("/python") >= 0 or obj_instance.Executable.startswith("python")

            lst_accessed_packages, unpackaged_accessed_code_files = G_FilesToPackagesCache.get_packages_list(
                self.m_accessedCodeFiles)

            fd_docker_file.write("# Package installations:\n")
            for nam_package in sorted(lst_accessed_packages):
                install_linux_package(fd_docker_file, nam_package)
            fd_docker_file.write("\n")
            fd_docker_file.write("# Non-packaged executable files copies:\n")
            sort_accessed_code_files = sorted(unpackaged_accessed_code_files, key=lambda x: x.Name)
            for objDataFile in sort_accessed_code_files:
                fil_nam = objDataFile.Name
                if not fil_nam.startswith(("/etc/", "/usr/")):
                    add_to_docker_dir(fil_nam, "Binary dependency")

    _dependencies_list = [
        DependencyPython(),
        DependencyPerl(),
        DependencyBinary(),
    ]

    accessed_data_files = set()

    # This is the complete list of extra executables which have to be installed.
    lst_binary_executables = set()

    # This is a subset of _dependencies_list.
    set_useful_dependencies = set()

    for obj_path, obj_instance in CIM_Process.m_G_map_cache_objects.items():
        for one_dep in _dependencies_list:
            # Based on the executable of the process,
            # this tells if we might have dependencies of this type: Python Perl etc...
            if one_dep.is_dependency_of(obj_instance):
                set_useful_dependencies.add(one_dep)
                break

        for fil_acc in obj_instance.m_ProcessFileAccesses:
            one_file = fil_acc.m_objectCIM_DataFile
            if one_dep and one_dep.is_executable_file(one_file):
                one_dep.add_file_dependency(one_file)
            else:
                accessed_data_files.add(one_file)

        try:
            an_exec = obj_instance.m_ExecutableObject
            # sys.stdout.write("Add exec=%s tp=%s\n" % (an_exec,str(type(an_exec))))
            lst_binary_executables.add(an_exec)
        except AttributeError:
            pass

    # Install or copy the executables.
    # Beware that some of them are specifically installed: Python, Perl.
    fd_docker_file.write("################################# Executables:\n")
    lst_packages, unknown_binaries = G_FilesToPackagesCache.get_packages_list(lst_binary_executables)
    for an_exec in sorted(lst_packages):
        install_linux_package(fd_docker_file, an_exec)
    fd_docker_file.write("\n")

    # This must be done after the binaries are installed: For example installing Perl packages
    # with CPAN needs to install Perl.
    fd_docker_file.write("################################# Dependencies by program type\n")
    for one_dep in set_useful_dependencies:
        fd_docker_file.write("# Dependencies: %s\n" % one_dep.DependencyName)
        one_dep.generate_docker_dependencies(fd_docker_file)
        fd_docker_file.write("\n")

    # These are not data files.
    categories_not_include = {
        "Temporary files",
        "Pipes and terminals",
        "Kernel file systems",
        "System config files",
        "Connected TCP sockets",
        "Other TCP/IP sockets",
    }

    lst_packages_data, unpackaged_data_files = G_FilesToPackagesCache.get_packages_list(accessed_data_files)

    set_python_modules, unknown_data_files = _files_to_python_modules(unpackaged_data_files)

    if set_python_modules:
        fd_docker_file.write("# Python modules:\n")
        for one_py_modu in sorted(set_python_modules):
            install_pip_module(fd_docker_file, one_py_modu)
        fd_docker_file.write("\n")

    fd_docker_file.write("# Data packages:\n")
    # TODO: Many of them are probably already installed.
    for an_exec in sorted(lst_packages_data):
        install_linux_package(fd_docker_file, an_exec)
    fd_docker_file.write("\n")

    if unknown_data_files:
        fd_docker_file.write("# Data files:\n")
        # Sorted by alphabetical order.
        sorted_dat_fils = sorted(unknown_data_files, key=lambda x: x.Name)
        for dat_fil in sorted_dat_fils:
            # DO NOT ADD DIRECTORIES.

            if dat_fil.Category in categories_not_include:
                continue

            fil_nam = dat_fil.Name
            if fil_nam.startswith(("/usr/", "/etc/", "UnknownFileDescr:")):
                continue
            if fil_nam in ["-1", "stdin", "stdout", "stderr", "."]:
                continue

            # Primitive tests so that directories are not copied.
            if fil_nam.endswith(("/.", "/")):
                continue

            add_to_docker_dir(fil_nam, dat_fil.Category)
    fd_docker_file.write("\n")

################################################################################

