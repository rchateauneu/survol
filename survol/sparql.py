#!/usr/bin/python

"""
This SPARQL server translates SPARQL queries into Survol data model.
"""

# For the moment, it just displays the content of the input to standard error,
# so the SparQL protocol can be analysed.

# See Experimental/Test_package_sparqlwrapper.py

import os
import sys
import cgi
#import html
import lib_util
import lib_kbase
import rdflib

# HTTP_HOST and SERVER_NAME and SERVER_PORT

# QUERY_STRING="query=%0A++++PREFIX+rdfs%3A+%3Chttp%3A/www.w3.org/2000/01/rdf-schema%23%3E%0A++++SELECT+%3Flabel%0A++++WHERE+%7B+%3Chttp%3A/dbpedia.org/resource/Asturias%3E+rdfs%3Alabel+%3Flabel+%7D%0A&output=json&results=json&format=json"

#https://docs.aws.amazon.com/neptune/latest/userguide/sparql-api-reference-mime.html
#
# You can choose the MIME type of a SPARQL response by sending an "Accept: type" header with the request.
# For example, curl -H "Accept: application/nquads ...".
# The available content types depend on the SPARQL query type.
#
# SELECT
#    application/sparql-results+json Default
#    application/sparql-results+xml
#    application/x-binary-rdf-results-table
#    text/tab-separated-values
#    text/csv
# ASK
#    application/sparql-results+json Default
#    application/sparql-results+xml
#    text/boolean
# CONSTRUCT
#    application/n-quads Default
#    application/rdf+xml
#    application/ld+json
#    application/n-triples
#    text/turtle
#    text/n3
#    application/trix
#    application/trig
#    application/sparql-results+json
# DESCRIBE
#    application/n-quads Default
#    application/rdf+xml
#    application/ld+json
#    application/n-triples
#    text/turtle
#    text/n3
#    application/trix
#    application/trig
#    application/sparql-results+json


def Main():
    arguments = cgi.FieldStorage()
    sys.stderr.write("\n")
    for i in arguments.keys():
        sys.stderr.write("%s => %s\n"%(i,arguments[i].value))
    sys.stderr.write("\n")

    # It seems that the package SPARQLWrapper uses CGI variables to specify
    # the expected output type.
    # FieldStorage(
    #   None,
    #   None,
    #   [
    #       MiniFieldStorage(
    #          'query',
    #           '\n    PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>\n    SELECT ?label\n    WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }\n'),
    #       MiniFieldStorage('output', 'json'),
    #       MiniFieldStorage('results', 'json'),
    #       MiniFieldStorage('format', 'json')])

    output_type = arguments["output"].value

    sys.stderr.write("output_type=%s\n"%output_type)

    # Only "xml" works OK.
    if output_type == "json":
        mime_format = 'application/json'
        rdflib_format='json'
    elif output_type == "json-ld":
        mime_format = 'application/json'
        rdflib_format='json-ld'
    elif output_type == "xml":
        mime_format = 'application/xml'
        rdflib_format='xml'
    else:
        sys.stderr.write("Invalid output type:%s\n"%output_type)
        raise Exception("Invalid output type:"+output_type)
    sys.stderr.write("mime_format=%s\n"%mime_format)
    sys.stderr.write("rdflib_format=%s\n"%rdflib_format)

    grph = lib_kbase.MakeGraph()

    nodeSubject = lib_kbase.MakeNodeLiteral("Subject")
    nodeObject = lib_kbase.MakeNodeLiteral("Object")
    nodeUrl = lib_kbase.MakeNodeUrl("http:/dbpedia.org/resource/Asturias")
    nodeUrl2 = lib_kbase.MakeNodeUrl("http://cmst.eu/articles/extracting-use-case-scenarios-and-domain-models-from-legacy-software/")
    primns = "http://primhillcomputers.com/survol"
    nodePred = lib_kbase.MakeNodeUrl( primns + "/" + "Hello" )
    nodePred2 = lib_kbase.MakeNodeUrl( primns + "/" + "Hello2" )
    grph.add( ( nodeUrl2, nodePred, nodeObject ) )
    grph.add( ( nodeUrl, nodePred, nodeSubject ) )
    grph.add( ( nodeUrl2, nodePred2, nodeSubject ) )

    sys.stderr.write("len grph=%d\n"%len(grph))
    lib_util.WrtHeader(mime_format)
    sys.stderr.write("mime_format=%s\n"%mime_format)
    try:
        # pip install rdflib-jsonld
        # No plugin registered for (json-ld, <class 'rdflib.serializer.Serializer'>)
        # rdflib_format = "pretty-xml"
        # strJson = grph.serialize( destination = None, format = rdflib_format)
        sys.stderr.write("len grph=%d\n"%len(grph))
        strJson = grph.serialize(format=rdflib_format)
        # strJson = grph.serialize(format='json-ld', indent=4)
    except Exception as exc:
        sys.stderr.write("Caught:%s\n"%exc)
        return
    sys.stderr.write("strJson=%s\n"%strJson)
    lib_util.WrtAsUtf(strJson)

    #qrySparql = arguments["query"].value
    #sys.stderr.write("qrySparql=%s\n"%html.escape(qrySparql))

    # This is the correct and expected output.

    #PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>
    #SELECT ?label
    #WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }

    # Extracts the predicates and the classes.

    # For each predicate, get the list of scripts returning data for this predicate.
    # This -possibly- implies classes (But this is not sure).
    # Maybe this is only true for the function __init__.AddInfo().
    # But this is a hint to identify the class of each variable.

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

