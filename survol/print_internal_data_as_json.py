#!/usr/bin/env python

# This is a technical script used only for testing.
# It depends only on low-level libraries and returns their internal results
# which cannot not normally be printed clearly.
# BEWARE: This does not work with WSGI.

import json
import sys

import lib_util

internal_data = {
    "uriRoot": lib_util.uriRoot,
    "HttpPrefix": lib_util.HttpPrefix(),
    "RootUri": lib_util.RootUri(),
    "RequestUri": lib_util.RequestUri()
}
json_data = json.dumps(internal_data)

sys.stdout.write(
"""Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept
Access-Control-Allow-Methods: POST,GET,OPTIONS
Access-Control-Allow-Origin:*
Content-Type: application/json; charset=utf-8
Content-Length: %d

""" % len(json_data)
)

ret_dict = {
    "uriRoot": lib_util.uriRoot,
    "HttpPrefix": lib_util.HttpPrefix(),
    "RootUri": lib_util.RootUri(),
    "RequestUri": lib_util.RequestUri()
}

sys.stdout.write(json_data)