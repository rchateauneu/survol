#!/usr/bin/python

"""
This SPARQL server translates SPARQL queries into Survol data model.
"""

# For the moment, it just displays the content of the input the standard error,
# so the SparQL protocol can be analysed.

import os
import sys
import cgi
import html


# HTTP_HOST and SERVER_NAME and SERVER_PORT

# QUERY_STRING="query=%0A++++PREFIX+rdfs%3A+%3Chttp%3A/www.w3.org/2000/01/rdf-schema%23%3E%0A++++SELECT+%3Flabel%0A++++WHERE+%7B+%3Chttp%3A/dbpedia.org/resource/Asturias%3E+rdfs%3Alabel+%3Flabel+%7D%0A&output=json&results=json&format=json"


def Main():
    sys.stdout.write("Content-type: text/html\n\n")

    sys.stdout.write("""
    <head>
     <title>SPARQL endpoint</title>
    </head>""")

    sys.stdout.write("""
    <body>
    """)

    arguments = cgi.FieldStorage()
    sys.stdout.write("<table>" )
    for i in arguments.keys():
        sys.stderr.write("<tr><td>%s</td><td>%s</td></tr>\n"%(i,arguments[i].value))
    sys.stdout.write("</table>" )

    qrySparql = arguments["query"].value
    sys.stdout.write("<br>qrySparql=%s\n"%html.escape(qrySparql))


    sys.stdout.write("""
    </body></html>
    """)

    # Extracts the predicates and the classes.

    # For each predicate, get the list of scripts returning data for this predicate.
    # This -possibly- implies classes (But this is not sure).
    # Maybe this is only true for the function __init__.AddInfo().
    # But this is a hint to idntify the class of each variable.

    # Also, rdf:type may be given for some variables.

    # For each variable whose class is identified, or suggested.
    # For each variable of a given class, see if there are values for each attribute
    # of its ontology.

    # If yes, it means that the object can be identified.
    # Then take the list of scripts for this class, returning these predicates.
    # Possibly all scripts: Not many data should be returned.

    # If no, we cannot identify the variable, then use the function Search() for this class,
    # with the few key-value pairs if the object is a literal.
    # There could be a default Search() function based on WMI or WBEM,
    # but this is optional, because possibly very slow.
    # There must be an upper limit on the number of objects returned by Search().

    # Joins will be done by SPARQL: The goal is only to feed the triplestore
    # with enough fresh data from scripts.




if __name__ == '__main__':
    Main()

