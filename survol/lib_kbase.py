# Reimplement some features of rdflib

import rdflib

def IsLiteral(objRdf):
	return isinstance(objRdf, (rdflib.term.Literal))

def IsLink(obj):
	return isinstance( obj , (rdflib.URIRef, rdflib.BNode))

def MakeNodeLiteral(value):
	return rdflib.Literal(value)

def MakeNodeUrl(url):
	return rdflib.term.URIRef(url)

#def MakeUriRef(url):
#	return rdflib.URIRef(url)

def MakeNamespace(primns):
	pc = rdflib.Namespace(primns)
	return pc

def MakeGraph():
	return rdflib.Graph()
