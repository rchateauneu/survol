#!/usr/bin/python

"""
This SPARQL server translates SPARQL queries into Survol data model.
"""


# For the moment, it just displays the content of the input the standard error,
# so the SparQL protocol can be analysed.

#!/usr/bin/python

# This is used for testing only.
# The output is plain HTML.

#!/usr/bin/python

# This is used for testing only.
# The output is plain HTML.

import os
import sys
import cgi

# HTTP_HOST and SERVER_NAME and SERVER_PORT

# QUERY_STRING="query=%0A++++PREFIX+rdfs%3A+%3Chttp%3A/www.w3.org/2000/01/rdf-schema%23%3E%0A++++SELECT+%3Flabel%0A++++WHERE+%7B+%3Chttp%3A/dbpedia.org/resource/Asturias%3E+rdfs%3Alabel+%3Flabel+%7D%0A&output=json&results=json&format=json"


def Main():
    print("""Content-type: text/html

    <head>
     <title>SPARQL endpoint</title>
    </head>
    <body>
    Test
    </body></html>
    """)

    start = '..'
    sources = '/sources'
    rootdir = start + sources
    sys.stderr.write("===================================================\n" )
    sys.stderr.write("getcwd=%s\n"% os.getcwd() )
    sys.stderr.write("Dir=%s\n"% rootdir )

    for key, value in os.environ.items():
        sys.stderr.write("K=%s V=%s\n" % ( key, value ) )
    sys.stderr.write("___________________________________________________\n" )

    arguments = cgi.FieldStorage()
    for i in arguments.keys():
        sys.stderr.write("%s = %s\n"%(i,arguments[i].value))

    # PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>
    # SELECT ?label
    # WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }
    qrySparql = arguments["query"].value
    sys.stderr.write("qrySparql:%s\n"%(qrySparql))



if __name__ == '__main__':
    Main()

