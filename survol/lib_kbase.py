# Reimplement some features of rdflib

import rdflib
import sys

def IsLiteral(objRdf):
	return isinstance(objRdf, (rdflib.term.Literal))

def IsLink(obj):
	return isinstance( obj , (rdflib.URIRef, rdflib.BNode))

def MakeNodeLiteral(value):
	return rdflib.Literal(value)

# This returns an object which, whose string conversion is identical to the input string.
# Beware that it is tometimes called recursively.
def MakeNodeUrl(url):
	uriRef = rdflib.term.URIRef(url)
	# sys.stderr.write("MakeNodeUrl url=%s uriRef=%s\n"%(url,uriRef))
	return uriRef

#def MakeUriRef(url):
#	return rdflib.URIRef(url)

def MakeNamespace(primns):
	pc = rdflib.Namespace(primns)
	return pc

def MakeGraph():
	return rdflib.Graph()
