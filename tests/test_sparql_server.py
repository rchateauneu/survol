#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import xml
import json
import unittest
import pkgutil

try:
    import SPARQLWrapper
except ImportError as exc:
    SPARQLWrapper = None
    print("Error importing:",exc)

from init import *

update_test_path()

# If the Survol agent does not exist, this script starts a local one.
_remote_sparql_server_process = None
_remote_sparql_test_agent = "http://%s:%d" % (CurrentMachine, RemoteSparqlTestServerPort)


def setUpModule():
    global _remote_sparql_server_process
    _remote_sparql_server_process, _agent_url = start_cgiserver(RemoteSparqlTestServerPort)
    assert _agent_url == _remote_sparql_test_agent


def tearDownModule():
    global _remote_sparql_server_process
    stop_cgiserver(_remote_sparql_server_process)


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
def _sparql_results_xml_to_json(results_xml):
    head_array = []
    results_array = []
    node_sparql = results_xml.getElementsByTagName("sparql")[0]
    for node_head in node_sparql.getElementsByTagName("head"):
        for node_variable in node_head.getElementsByTagName("variable"):
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
    json_result = {"head": {"vars": head_array}, "results": {"bindings": results_array}}
    print("json_result=",json_result)
    return json_result


# https://stackoverflow.com/questions/5888020/sparql-query-on-the-remote-remote-endpoint-rdflib-redland

def _url_to_sparql_result(url_rdf, sparql_query, format_str):
    """This returns the result as a dictionary of dictionaries"""

    print("_url_to_sparql_result url_rdf=", url_rdf, " format_str=", format_str)

    sparql_wrapper = SPARQLWrapper.SPARQLWrapper(url_rdf)
    sparql_wrapper.setQuery(sparql_query)

    str_to_format = {
        "XML": SPARQLWrapper.XML,
        "JSON": SPARQLWrapper.JSON
    }[format_str]

    sparql_wrapper.setReturnFormat(str_to_format)
    sparql_qry_result = sparql_wrapper.query()
    results_http_convert = sparql_qry_result.convert()

    print("SPARQLWrapper.__version__=", SPARQLWrapper.__version__)
    print("_url_to_sparql_result type(results_convert)=", type(results_http_convert))
    print("_url_to_sparql_result results_convert=", results_http_convert)

    print("AFTER EXECUTION ==================================")
    if format_str == "XML":
        # Specific conversion of XML Sparql results to JSON, so we can use the same results data.
        assert isinstance(results_http_convert, xml.dom.minidom.Document)
        results_chopped_xml_to_json = _sparql_results_xml_to_json(results_http_convert)
        assert results_chopped_xml_to_json
        return results_chopped_xml_to_json
    elif format_str == "JSON":
        assert isinstance(results_http_convert, dict)
        return results_http_convert
    else:
        raise Exception("Invalid format:", format_str)


def run_remote_sparql_query(sparql_query, format_str):
    """This executes a query to the Sparql server of the current machine, via TCP/IP."""
    print("run_remote_sparql_query sparql_query=", sparql_query)

    url_sparql = _remote_sparql_test_agent + "/survol/sparql.py"

    sparql_result = _url_to_sparql_result(url_sparql, sparql_query, format_str)
    return sparql_result

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

    These queries are already tested locally.
    """

    def test_server_CIM_Process_xml(self):
        """
        This gets the pid of the current process and gets the result in RDF-XML.
        """
        sparql_query = """
            PREFIX survol:  <http://www.primhillcomputers.com/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?pid
            WHERE
            {
                ?url_proc rdf:type survol:CIM_Process .
                ?url_proc survol:Description 'python.exe' .
                ?url_proc survol:Handle ?pid .
            }
            """
        sparql_result_json = run_remote_sparql_query(sparql_query, "XML")
        print("test_server_CIM_Process_xml: sparql_result_json=", sparql_result_json)
        self.assertEqual(sparql_result_json["head"]["vars"][0], "pid")

    def test_server_CIM_Process_json(self):
        """
        This gets the pid of the current process and gets the result in JSON.
        """
        sparql_query = """
            PREFIX survol:  <http://www.primhillcomputers.com/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?pid
            WHERE
            {
                ?url_proc rdf:type survol:CIM_Process .
                ?url_proc survol:Description 'python.exe' .
                ?url_proc survol:Handle ?pid .
            }
            """
        sparql_result_json = run_remote_sparql_query(sparql_query, "JSON")
        print("test_server_CIM_Process_json: sparql_result_json=", sparql_result_json)
        self.assertEqual(sparql_result_json["head"]["vars"][0], "pid")

    def test_server_all_CIM_Process_json(self):
        """
        This tests the ability to read all remote process ids in JSON format.
        """
        sparql_query = """
            PREFIX survol:  <http://www.primhillcomputers.com/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?pid
            WHERE
            {
                ?url_proc rdf:type survol:CIM_Process .
                ?url_proc survol:Handle ?pid .
            }
            """
        sparql_result_json = run_remote_sparql_query(sparql_query, "JSON")
        print("test_server_all_CIM_Process_json: sparql_result_json=", sparql_result_json)
        print("head=", sparql_result_json["head"])
        print("vars=", sparql_result_json["head"]["vars"])
        self.assertEqual(sparql_result_json["head"]["vars"][0], "pid")

        pids_list = [one_result["pid"]["value"] for one_result in sparql_result_json["results"]["bindings"]]
        print("test_server_all_CIM_Process_json: pids_list=", pids_list)
        # At least a handful of processes.
        self.assertTrue(len(pids_list) > 1)


if __name__ == '__main__':
    assert SPARQLWrapper
    unittest.main()
