#!/usr/bin/python

"""
Mandatory SPARQL end-point

It extracts data from Survol, WMI or WBEM, then runs a Sparql query on the current RDF triplestore.
This triplestore can also be updated by events.
"""

import os
import re
import sys
import json
import xml.etree.cElementTree as ET
import logging

import lib_util
import lib_common
import lib_kbase
import lib_sparql
import lib_wmi
import lib_sparql_callback_survol
import lib_export_ontology

# For the moment, it just displays the content of the input to standard error,
# so the SparQL protocol can be analysed.

# See Experimental/Test_package_sparqlwrapper.py

# http://timgolden.me.uk/python/downloads/wmi-0.6b.py

lib_util.SetLoggingConfig(logging.DEBUG)

# This is a SPARQL server which executes the query with WMI data.
def Main():
    lib_util.SetLoggingConfig(logging.ERROR)
    # envSparql = lib_sparql.SparqlEnvironment()

    # https://hhs.github.io/meshrdf/sparql-and-uri-requests

    # Parameter name, SELECT queries, CONSTRUCT queries, default, help.
    # format
    # Accepts HTML*, XML, CSV, TSV or JSON
    # Accepts HTML*, XML, JSON-LD, RDF/XML, TURTLE or N3
    # Default: HTML*
    # Returns a file with the specified syntax.

    # inference
    # Accepts true or false
    # Accepts true or false
    # Default: false
    # Running a query with inference set to "true" will return results
    # for all subclasses and subproperties of those classes and properties you specify in your query.
    # For example, there are no direct instances of meshv:Descriptor,
    # but if you run a query with inference and look for rdf:type meshv:Descriptor,
    # you will get all instances of meshv:Descriptor's subclasses - meshv:TopicalDescriptor,
    # meshv:GeographicalDescriptor, meshv:PublicationType and meshv:CheckTag.
    # Running a query with inference=true may affect performance.

    # limit
    # Accepts positive integers up to 1000
    # N/A
    # Default: 1000
    # Limits the number of results per request. The maximum number of results per request for SELECT queries is 1,000.
    # This parameter does not affect CONSTRUCT queries.
    # CONSTRUCT queries will return all triples requested up to a limit of 10,000 triples.

    # offset
    # Accepts positive integers
    # N/A
    # Default: 0
    # When offset=n, this parameter will return results starting with the nth result.
    # Use this parameter to loop through multiple requests for large result sets.

    # query
    # Accepts a SELECT SPARQL query
    # Accepts a CONSTRUCT SPARQL query
    # Default: N/A
    # This parameter is required and must contain a SPARQL query. For an example of how these are formatted,
    # run a query from the SPARQL query editor and view the resulting URL.

    # year
    # Accepts "current" or a year.
    # Accepts "current" or a year.
    # Default: current
    # Queries either the current MeSH graph (http://id.nlm.nih.gov/mesh) or a versioned MeSH graph,
    # for example: (http://id.nlm.nih.gov/mesh/2015).
    import cgi
    arguments = cgi.FieldStorage()

    # See lib_uris.SmbShareUri and the HTTP server which collapses duplicated slashes "//" into one,
    # in URL, because they are interpreted as file names.
    # SparqlWrapper does not encode slashes with urllib.quote_plus(param.encode('UTF-8'), safe='/')
    # in Wrapper.py.
    # See modules CGIHTTPServer, BaseHTTPServer, CGIHTTPRequestHandler
    # 'HTTP_USER_AGENT': 'sparqlwrapper 1.8.4 (rdflib.github.io/sparqlwrapper)'
    # sys.stderr.write("Environ=%s\n"%str(os.environ))
    # QUERY_STRING='query=%0A++++++++++++++++PREFIX+wmi%3A++%3Chttp%3A/www.primhillcomputers.com/ontology/wmi%23%3E%0A++++++++++++++++PREFIX+survol%3A++%3Chttp%3A/primhillcomputers.com/survol%23%3E%0A++++++++++++++++PREFIX+rdfs%3A++++%3Chttp%3A/www.w3.org/2000/01/rdf-schema%
    # 23%3E%0A++++++++++++++++SELECT+%3Fcaption%0A++++++++++++++++WHERE%0A++++++++++++++++%7B%0A++++++++++++++++++++%3Furl_user+rdf%3Atype+survol%3AWin32_UserAccount+.%0A++++++++++++++++++++%3Furl_user+survol%3AName+%27rchateau%27+.%0A++++++++++++++++++++%3Furl_user+sur
    # vol%3ACaption+%3Fcaption+.%0A++++++++++++++++++++%3Furl_user+rdfs%3AseeAlso+%22WMI%22+.%0A++++++++++++++++%7D%0A++++++++++++++++&output=json&results=json&format=json'
    sparql_query = arguments["query"].value

    # 'SERVER_SOFTWARE': 'SimpleHTTP/0.6 Python/2.7.10'
    if os.environ['SERVER_SOFTWARE'].startswith("SimpleHTTP"):
        sparql_query = re.sub("([^a-z]*)http:/([^a-z]*)", r"\1http://\2", sparql_query)

    sys.stderr.write("sparql_server sparql_query=%s\n" % sparql_query.replace(" ","="))

    try:
        result_format = arguments["format"].value
    except KeyError:
        result_format = "HTML*"

    sys.stderr.write("\n")

    grph = lib_kbase.MakeGraph()

    prefix_to_callbacks = {
        "WMI": lib_wmi.WmiSparqlCallbackApi(),
        "survol": lib_sparql_callback_survol.SurvolSparqlCallbackApi(),
    }

    objectUnitTestCallbackApi = lib_sparql.SwitchCallbackApi(prefix_to_callbacks)

    lib_sparql.QueryToGraph(grph, sparql_query, objectUnitTestCallbackApi )

    # See lib_common.py : This added to any RDF document.
    ###########lib_export_ontology.Grph2Rdf(grph)

    # At this stage, we must run the Sparql query on the generated RDF triplestore.

    # envSparql.WriteTripleStoreAsString(grph)

    # qres = g.query(
    #     """SELECT DISTINCT ?aname ?bname
    #        WHERE {
    #           ?a foaf:knows ?b .
    #           ?a foaf:name ?aname .
    #           ?b foaf:name ?bname .
    #        }""")
    #
    # for row in qres:
    #     print("%s knows %s" % row)

    sys.stderr.write("Before query len(grph)=%d\n" % len(grph))
    for s,p,o in grph:
        sys.stderr.write("s=%s p=%s o=%s\n" % (s,p,o))

    sys.stderr.write("sparql_server sparql_query=%s\n" % sparql_query)
    query_result = grph.query(sparql_query)
    sys.stderr.write("sparql_server After query len(query_result)=%d\n" % len(query_result))
    sys.stderr.write("sparql_server After query query_result=%s\n" % str(query_result))

    #exit(0)

    # TODO: This does not work "select *", so maybe should read the first row.
    row_header = lib_sparql.QueryHeader(sparql_query)

    # https://docs.aws.amazon.com/neptune/latest/userguide/sparql-api-reference-mime.html

    if result_format.upper() == "JSON":
        mime_format = "application/sparql-results+json"
        # https://www.w3.org/TR/2013/REC-sparql11-results-json-20130321/
        # This document describes how to serialize SPARQL results (SELECT and ASK query forms) in a JSON format.
        # {
        #     "head": {"vars": ["book", "title"]
        #              },
        #     "results": {
        #         "bindings": [
        #             {
        #                 "book": {"type": "uri", "value": "http://example.org/book/book6"},
        #                 "title": {"type": "literal", "value": "Harry Potter and the Half-Blood Prince"}
        #             },
        bindings_list = []
        for one_row in query_result:
            dict_row = {}
            for ix in range(len(row_header)):
                one_element = one_row[ix]

                if lib_kbase.IsLiteral(one_element):
                    json_element = {"type":"literal", "value": str(one_element)}
                elif lib_kbase.IsURIRef(one_element):
                    json_element = {"type":"url", "value": str(one_element)}
                else:
                    raise Exception("SparqlServer: Invalid type:%s"%str(one_element))
                one_variable = row_header[ix]
                dict_row[one_variable] = json_element

            bindings_list.append(dict_row)
        sys.stderr.write("bindings_list=%s\n"%str(bindings_list))

        json_output = {
            "head": {"vars": row_header},
            "results": {"bindings": bindings_list}}
        str_output = json.dumps(json_output)
    elif result_format.upper() == "XML":
        mime_format = "application/sparql-results+xml"
        # https://www.w3.org/TR/rdf-sparql-XMLres/
        # This document describes an XML format for the variable binding and boolean results formats provided by the SPARQL query language for RDF
        # <?xml version="1.0"?>
        # <sparql xmlns="http://www.w3.org/2005/sparql-results#">
        #   <head>
        #     <variable name="x"/>
        #     <variable name="hpage"/>
        #   </head>
        #
        #   <results>
        #     <result>
        #       <binding name="x"> ... </binding>
        #       <binding name="hpage"> ... </binding>
        #     </result>

        root = ET.Element("sparql")
        head = ET.SubElement(root, "head")
        for one_variable in row_header:
            ET.SubElement(head, "variable", name=one_variable)

        results = ET.SubElement(root, "results")
        for one_row in query_result:
            result = ET.SubElement(results, "result")
            for ix in range(len(row_header)):
                one_variable = row_header[ix]
                ET.SubElement(result, "binding", name=one_variable).text = one_row[ix]

        str_output = ET.tostring(root, encoding='utf8', method='xml')
        sys.stderr.write("sparql_server str_output=%s\n"%str_output)

    else:
        raise Exception("Results format %s not implemented yet"%result_format)

    sys.stderr.write("sparql_server result_format=%s str_output=%s\n"%(result_format, str_output))

    lib_util.WrtHeader(mime_format)
    lib_util.WrtAsUtf(str_output)

if __name__ == '__main__':
    Main()


