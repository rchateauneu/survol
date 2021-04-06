#!/usr/bin/env python

"""
Put an event about a CIM object
"""

import os
import io
import six
import sys
import cgi
import json
import time
import rdflib
import logging
import traceback
import lib_util
import lib_common
import lib_event
import lib_kbase

# This receives a CIM class and a pair of attributes which should be enough to create a CIM object.
# In the temp directory, there is one sub-directory per CIM class, and in these,
# one file per CIM object, defined with its attributes.
# These files are created by event_put, and read and deleted by event_get.py.
# The type of the data stored in these files is exactly what can be returned by any scripts.


# FIXME: This can be a lot simplified. This code results of the research of an intermittent time-out
# FIXME: ... on Windows and Python 3 and if the test agent is started by pytest.
def _get_graph_from_stdin(http_content_length):
    """This reads stdin from the HTTP client and returns a rdflib graph."""
    read_bytes_number = 0
    loaded_bytes = b""
    rest_to_read = http_content_length
    loop_counter = 0
    while True:
        if lib_util.is_py3:
            loaded_chunk = sys.stdin.buffer.read(rest_to_read)
        else:
            loaded_chunk = sys.stdin.read(rest_to_read)
        assert isinstance(loaded_chunk, six.binary_type)
        chunk_length = len(loaded_chunk)
        loaded_bytes += loaded_chunk
        rest_to_read -= chunk_length
        read_bytes_number += chunk_length
        if read_bytes_number >= http_content_length:
            break
        loop_counter += 1
        time.sleep(0.5)
        if loop_counter > 5:
            # The end of the message might be lost. The beginning is OK.
            # event_put.py chunk_length=24820
            # ...
            # event_put.py too many loops rest_to_read=725492
            logging.error("Too many loops. read_bytes_number=%d" % read_bytes_number)
            raise Exception("Too many loops. read_bytes_number=%d" % read_bytes_number)

    if loop_counter > 1:
        logging.warning("BEWARE loop_counter=%d", loop_counter)

    if len(loaded_bytes) != http_content_length:
        raise Exception("len(loaded_bytes)=%d http_content_length=%d" %(len(loaded_bytes), http_content_length))
    if read_bytes_number != http_content_length:
        raise Exception("read_bytes_number=%d http_content_length=%d" %(read_bytes_number, http_content_length))
    bytes_stream = io.BytesIO(loaded_bytes)

    rdflib_graph = rdflib.Graph()
    rdflib_graph.parse(bytes_stream, format="application/rdf+xml")
    return rdflib_graph

# TODO: Tested with Win7 py2.7
# TODO: The goal is to read a rdflib document without an intermediate string.
def _get_graph_from_stdin_DRAFT(http_content_length):
    """This reads stdin from the HTTP client and returns a rdflib graph."""
    if lib_util.is_py3:
        #bytes_stream = sys.stdin.buffer
        bytes_stream = sys.stdin
    else:
        bytes_stream = sys.stdin

    rdflib_graph = rdflib.Graph()
    rdflib_graph.parse(bytes_stream, format="application/rdf+xml")
    return rdflib_graph


def Main():
    logging.getLogger().setLevel(logging.DEBUG)

    lib_common.set_events_credentials()

    time_start = time.time()
    http_content_length = int(os.environ['CONTENT_LENGTH'])

    # https://stackoverflow.com/questions/49171591/inets-httpd-cgi-script-how-do-you-retrieve-json-data
    # The script MUST NOT attempt to read more than CONTENT_LENGTH bytes, even if more data is available.
    logging.debug("http_content_length=%d time_start=%f", http_content_length, time_start)

    extra_error_status = ""
    try:
        rdflib_graph = _get_graph_from_stdin(http_content_length)
        time_loaded = time.time()

        triples_number = len(rdflib_graph)
        files_updates_total_number = lib_kbase.write_graph_to_events(None, rdflib_graph)

        time_stored = time.time()
        logging.debug("time_stored=%f files_updates_total_number=%d", time_stored, files_updates_total_number)

        server_result = {
            'success': 'true',
            'time_start': '%f' % time_start,
            'time_loaded': '%f' % time_loaded,
            'time_stored': '%f' % time_stored,
            'triples_number': '%d' % triples_number}
    except Exception as exc:
        logging.error("Exception=%s", exc)

        server_result = {
            'success': 'false',
            'time_start': '%f' % time_start,
            'error_message': '%s:%s:%s' % (str(exc), extra_error_status, traceback.format_exc())}

    json_output = json.dumps(server_result)
    sys.stdout.write('Content-Type: application/json\n')
    sys.stdout.write('Content-Length: %d\n\n' % len(json_output))
    sys.stdout.write(json_output)

if __name__ == '__main__':
    Main()
