#!/usr/bin/env python

"""
Put an event about a CIM object
"""

import os
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
	# cgiArguments = cgi.FieldStorage()

	# https://stackoverflow.com/questions/49171591/inets-httpd-cgi-script-how-do-you-retrieve-json-data
	# The script MUST NOT attempt to read more than CONTENT_LENGTH bytes, even if more data is available.
	tmStart = time.time()
	sys.stderr.write("event_put.py tmStart=%f\n" % (tmStart))
	try:
		myjson = json.load(sys.stdin)
		tmStart = time.time()
		numTriples = len(myjson)
		sys.stderr.write("event_put.py tmStart=%f myjson=%d triples received\n" % (tmStart,numTriples))

		lib_event.data_store_list(myjson)
		sys.stderr.write("event_put.py tmStart=%f myjson=%d triples stored\n" % (tmStart,numTriples))

		result = {'success':'true','message':'Tm=%f. NumTriples=%d' % ( tmStart, numTriples ) }
	except Exception as exc:
		sys.stderr.write("event_put.py Exception=%s\n" % (str(exc)))
		# sys.stderr.write("event_put.py Envs=%s\n" % (str(os.environ)))
		result = {'success':'false','message':'Tm=%f. Error:%s' % (tmStart, str(exc))}

	print( 'Content-Type: application/json\n\n' )
	print( json.dumps(result) )

	sys.stderr.write("event_put.py %d Result=%s\n" % (tmStart,str(result)))


if __name__ == '__main__':
	Main()
