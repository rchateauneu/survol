# Encapsulate rdflib features.

import rdflib
import sys

def IsLiteral(objRdf):
	return isinstance(objRdf, (rdflib.term.Literal))

def IsLink(obj):
	return isinstance( obj , (rdflib.URIRef, rdflib.BNode))

def MakeNodeLiteral(value):
	return rdflib.Literal(value)

# This returns an object which, whose string conversion is identical to the input string.
# Beware that it is sometimes called recursively.
def MakeNodeUrl(url):
	uriRef = rdflib.term.URIRef(url)
	# sys.stderr.write("MakeNodeUrl url=%s uriRef=%s\n"%(url,uriRef))
	return uriRef

def MakeNamespace(primns):
	pc = rdflib.Namespace(primns)
	return pc

def MakeGraph():
	return rdflib.Graph()

# objsList = lib_kbase.enumerate_objects_from_class(triplestoreA,self.m_src_B.m_class)
def enumerate_objects_from_class(triplestoreA,aClassName):
	return None
	# On va plutot mettre une fonction de match.
	# Or simply iterate.
	# qskjdhflqjkhsdfl

# This reasonably assumes that the triplestore library is able to convert from RDF.
def triplestore_from_rdf_xml(docXmlRdf):
	return None
	# qsdkjfmlqjskdfm

