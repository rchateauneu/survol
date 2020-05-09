#!/usr/bin/env python

"""
Put an event about a CIM object
"""

import os
import six
import sys
import cgi
import json
import time
import lib_event

# This receives a CIM class and a pair of attributes which should be enough to create a CIM object.
# In the temp directory, there is one sub-directory per CIM class, and in these,
# one file per CIM object, defined with its attributes.
# These files are created by event_put, and read and deleted by event_get.py.
# The type of the data stored in these files is exactly what can be returned by any scripts.

def Main():
    time_start = time.time()
    http_content_length = int(os.environ['CONTENT_LENGTH'])

    # https://stackoverflow.com/questions/49171591/inets-httpd-cgi-script-how-do-you-retrieve-json-data
    # The script MUST NOT attempt to read more than CONTENT_LENGTH bytes, even if more data is available.
    sys.stderr.write("event_put.py http_content_length=%d time_start=%f\n" % (http_content_length, time_start))

    # FIXME: This can be a lot simplified. This code results of the research of an intermittent time-out
    # FIXME: ... on Windows and Python 3 and if the test agent is started by pytest.
    extra_error_status = ""
    try:
        read_bytes_number = 0
        loaded_bytes = b""
        rest_to_read = http_content_length
        loop_counter = 0
        while True:
            if sys.version_info >= (3,):
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
            time.sleep(0.1)
            if loop_counter > 1000:
                raise Exception(__file__ + " too many loops. read_bytes_number=%d" % read_bytes_number)

        if loop_counter > 1:
            sys.stderr.write("event_put.py BEWARE loop_counter=%d\n" % loop_counter)

        if len(loaded_bytes) != http_content_length:
            raise Exception("len(loaded_bytes)=%d http_content_length=%d" %(len(loaded_bytes), http_content_length))
        if read_bytes_number != http_content_length:
            raise Exception("read_bytes_number=%d http_content_length=%d" %(read_bytes_number, http_content_length))
        triples_json = json.loads(loaded_bytes)
        time_loaded = time.time()
        triples_number = len(triples_json)

        files_updates_total_number = lib_event.store_events_triples_list(triples_json)
        time_stored = time.time()
        sys.stderr.write("event_put.py time_stored=%f files_updates_total_number=%d\n" % (time_stored, files_updates_total_number))

        server_result = {
            'success': 'true',
            'time_start': '%f' % time_start,
            'time_loaded': '%f' % time_loaded,
            'time_stored': '%f' % time_stored,
            'triples_number': '%d' % triples_number}
    except Exception as exc:
        sys.stderr.write("event_put.py Exception=%s\n" % str(exc))

        server_result = {
            'success': 'false',
            'time_start': '%f' % time_start,
            'error_message': '%s:%s' % (str(exc), extra_error_status)}

    json_output = json.dumps(server_result)
    sys.stdout.write('Content-Type: application/json\n')
    sys.stdout.write('Content-Length: %d\n\n' % len(json_output))
    sys.stdout.write(json_output)

if __name__ == '__main__':
    Main()
