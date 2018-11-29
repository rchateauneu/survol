# This is a technical script used only for testing.
# It depends only on low-level libraries and returns their internal results
# which cannot not normally be printed clearly.
import json
import sys

import lib_util

sys.stdout.write(
"""Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept
Access-Control-Allow-Methods: POST,GET,OPTIONS
Access-Control-Allow-Origin:*
Content-Type: application/json; charset=utf-8

"""
)

retDict = {
	"uriRoot":lib_util.uriRoot,
	"HttpPrefix" : lib_util.HttpPrefix(),
	"RootUri" : lib_util.RootUri(),
	"RequestUri" : lib_util.RequestUri()
}

sys.stdout.write(json.dumps(retDict))