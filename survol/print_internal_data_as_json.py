# This is a technical script used only for testing.
# It depends only on low-level libraries and returns their internal results
# which cannot not normally be printed clearly.
import json
import sys

sys.stdout.write(
"""Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept
Access-Control-Allow-Methods: POST,GET,OPTIONS
Access-Control-Allow-Origin:*
Content-Type: application/json; charset=utf-8

"""
)

retDict = {"Survol":"Internal data"}

sys.stdout.write(json.dumps(retDict))