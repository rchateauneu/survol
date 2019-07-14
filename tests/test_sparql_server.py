#!/usr/bin/python

from __future__ import print_function

import cgitb
import cgi
import os
import sys
import json
import unittest
import socket
import psutil

import SPARQLWrapper
import rdflib

# This loads the module from the source, so no need to install it, and no need of virtualenv.
sys.path.insert(0,"../survol")

import lib_util

# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()
try:
    CurrentUsername = os.environ["USERNAME"]
except KeyError:
    # This is for Linux.
    CurrentUsername = os.environ["USER"]

CurrentPid = os.getpid()
CurrentParentPid = psutil.Process().ppid()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"

# <?xml version="1.0" ?>
# <sparql><head><variable name="caption"/></head>
#   <results>
#       <result><binding name="caption">rchateau-HP\\rchateau</binding></result>
#   </results>
# </sparql>
#
# ['ATTRIBUTE_NODE', 'CDATA_SECTION_NODE', 'COMMENT_NODE', 'DOCUMENT_FRAGMENT_NODE', 'DOCUMENT_NODE',
# 'DOCUMENT_TYPE_NODE', 'ELEMENT_NODE', 'ENTITY_NODE', 'ENTITY_REFERENCE_NODE', 'NOTATION_NODE',
# 'PROCESSING_INSTRUCTION_NODE', 'TEXT_NODE', '__doc__', '__init__', '__module__', '__nonzero__',
# '_call_user_data_handler', '_child_node_types', '_create_entity', '_create_notation', '_elem_info',
# '_get_actualEncoding', '_get_async', '_get_childNodes', '_get_doctype', '_get_documentElement', '_get_documentURI',
# '_get_elem_info', '_get_encoding', '_get_errorHandler', '_get_firstChild', '_get_lastChild', '_get_localName',
# '_get_standalone', '_get_strictErrorChecking', '_get_version', '_id_cache', '_id_search_stack', '_magic_id_count',
# '_set_async', 'abort', 'actualEncoding', 'appendChild', 'async', 'attributes', 'childNodes', 'cloneNode',
# 'createAttribute', 'createAttributeNS', 'createCDATASection', 'createComment', 'createDocumentFragment',
# 'createElement', 'createElementNS', 'createProcessingInstruction', 'createTextNode', 'doctype', 'documentElement',
# 'documentURI', 'encoding', 'errorHandler', 'firstChild', 'getElementById', 'getElementsByTagName',
# 'getElementsByTagNameNS', 'getInterface', 'getUserData', 'hasChildNodes', 'implementation', 'importNode',
# 'insertBefore', 'isSameNode', 'isSupported', 'lastChild', 'load', 'loadXML', 'localName', 'namespaceURI',
# 'nextSibling', 'nodeName', 'nodeType', 'nodeValue', 'normalize', 'ownerDocument', 'parentNode', 'prefix',
# 'previousSibling', 'removeChild', 'renameNode', 'replaceChild', 'saveXML', 'setUserData', 'standalone',
# 'strictErrorChecking', 'toprettyxml', 'toxml', 'unlink', 'version', 'writexml']
def SparqlResultsXMLToJSON(results_xml):
    head_array = []
    results_array = []
    node_sparql = results_xml.getElementsByTagName("sparql")[0]
    for node_head in node_sparql.getElementsByTagName("head"):
        node_variable = node_head.getElementsByTagName("variable")[0]
        head_name = node_variable.getAttribute('name')
        head_array.append(head_name)
    node_results = node_sparql.getElementsByTagName("results")[0]
    for node_result in node_results.getElementsByTagName("result"):
        result_dict = {}
        for node_binding in node_result.getElementsByTagName("binding"):
            binding_name = node_binding.getAttribute('name')
            binding_text = node_binding.childNodes[0].nodeValue

            #{u'type': u'literal', u'value': u'S-1-5-21-3348735596-448992173-972389567-1001'}}

            result_dict[binding_name] = {u'type': u'literal', u'value': binding_text}
        results_array.append(result_dict)
    json_result = { "head": {"vars": head_array}, "results": { "bindings": results_array}}
    print("json_result=",json_result)
    return json_result


# https://stackoverflow.com/questions/5888020/sparql-query-on-the-remote-remote-endpoint-rdflib-redland

# This returns the result as a dictionary of dictionaries
def UrlToSparqlResult(url_rdf, sparql_query, format_str):
    # print("UrlToSparqlResult sparql_query=",sparql_query)
    print("UrlToSparqlResult url_rdf=",url_rdf," format_str=",format_str)

    sparql_wrapper = SPARQLWrapper.SPARQLWrapper(url_rdf)
    sparql_wrapper.setQuery(sparql_query)
    # print("sparql_wrapper:",str(dir(sparql_wrapper)))
    # print("sparql_wrapper.queryString:",sparql_wrapper.queryString)

    # JSON and JSONLD do not work.

    str_to_format = {
        "XML": SPARQLWrapper.XML,
        "JSON": SPARQLWrapper.JSON
    }[format_str]

    sparql_wrapper.setReturnFormat(str_to_format)
    sparql_qry_result = sparql_wrapper.query()
    results_conversion = sparql_qry_result.convert()

    if format_str == "XML":
        # Specific conversion of XML Sparql results to JSON, so we can use the same results data.
        print("dir(results_conversion)=",dir(results_conversion))
        print("results_conversion.toxml()=",results_conversion.toxml())
        results_conversion = SparqlResultsXMLToJSON( results_conversion )

    return results_conversion


    # https://www.w3.org/TR/2013/REC-sparql11-results-json-20130321/
    # {
    #     "head": {"vars": ["book", "title"]
    #              },
    #     "results": {
    #         "bindings": [
    #             {
    #                 "book": {"type": "uri", "value": "http://example.org/book/book6"},
    #                 "title": {"type": "literal", "value": "Harry Potter and the Half-Blood Prince"}
    #             },

    # This document describes an XML format for the variable binding and boolean results formats provided by the SPARQL query language for RDF
    #
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

class SparqlServerSurvolTest(unittest.TestCase):
    """
    Test the Sparql server which works on Survol data.
    """

    @staticmethod
    def run_compare_survol(sparql_query, expected_header, expected_dicts, format_str):

        print("run_compare_survol sparql_query=", sparql_query)

        url_sparql = RemoteTestAgent + "/survol/sparql.py"

        sparql_result = UrlToSparqlResult(url_sparql, sparql_query, format_str)


        # sparql_result ... = {
        # u'head': {u'vars': [u'caption']},
        # u'results': {
        #   u'bindings': [
        #       {u'caption': {u'type': u'literal', u'value': u'rchateau-HP\\\\rchateau'}},
        #       {u'caption': {u'type': u'literal', u'value': u'S-1-5-21-3348735596-448992173-972389567-1001'}},
        #       {u'caption': {u'type': u'url', u'value': u'http://primhillcomputers.com/survol/Win32_UserAccount'}},
        print("run_compare_survol sparql_result ... =", sparql_result)
        assert sparql_result['head']['vars'] == expected_header

        # This builds a set of tuples from the actual results.
        str_actual_data = set()
        for one_dict in sparql_result['results']['bindings']:
            values_tuple = tuple( ( one_variable, one_dict[one_variable][u'value'] ) for one_variable in expected_header)
            str_actual_data.add(values_tuple)
        print("run_compare_survol len(str_actual_data)=", len(str_actual_data))

        print("run_compare_survol expected_dicts=", expected_dicts)
        print("run_compare_survol str_actual_data=", str_actual_data)
        for one_dict in expected_dicts:
            print("run_compare_survol one_dict=",one_dict)
            assert(one_dict in str_actual_data)


    def test_server_survol(self):
        # PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
        """
        ?url_user rdf:type survol:Win32_UserAccount .
        ?url_user survol:Name '%s' .
        ?url_user survol:Caption ?caption .
        ?url_user rdfs:seeAlso "WMI" .
        """


        array_survol_queries=[
            [
                """
                PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
                PREFIX survol:  <http://primhillcomputers.com/survol#>
                PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
                SELECT ?caption
                WHERE
                {
                    ?url_user rdf:type survol:Win32_UserAccount .
                    ?url_user survol:Name '%s' .
                    ?url_user survol:Caption ?caption .
                    ?url_user rdfs:seeAlso "WMI" .
                }
                """ % CurrentUsername,
                [u'caption'],
                [
#                    (( u'caption', u'rchateau'),),
                    ((u'caption', u'rchateau-HP\\\\rchateau'),),
                ]
            ],
        ]


        for sparql_query, expected_header, expected_dicts in array_survol_queries:
            for fmt in ["XML","JSON"]:
                self.run_compare_survol(sparql_query, expected_header, expected_dicts, fmt)


if __name__ == '__main__':
    unittest.main()



