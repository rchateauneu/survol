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
# The returns the set of subjects or objects which match the predicate function.
# For example, the predicate tests the class of the url.
def enumerate_class_instances(grph,predicateFunction):
	instancesSet = set()
	# Beware that the order might change each time.
	for kSub,kPred,kObj in grph:
		if kSub not in instancesSet:
			if predicateFunction(kSub):
				instancesSet.add(kSub)

		if kObj not in instancesSet:
			if predicateFunction(kObj):
				instancesSet.add(kObj)
	return instancesSet


# This writes a triplestore to a stream which can be a socket or a file.
def triplestore_to_stream_xml(grph,out_dest):
	# With Py2 and StringIO or BytesIO, it raises "TypeError: unicode argument expected, got 'str'"
	# grph.serialize( destination = out_dest, format="xml")
	# There might be a way to serialize directory to the socket.
	strXml = grph.serialize( destination = None, format="xml")
	out_dest.write(strXml.decode('latin1'))


# This reasonably assumes that the triplestore library is able to convert from RDF.
# This transforms a serialize XML document into RDF.
# See: https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html
def triplestore_from_rdf_xml(docXmlRdf):
	# This is the inverse operation of: grph.serialize( destination = out_dest, format="xml")
	grph = rdflib.Graph()
	result = grph.parse(data=docXmlRdf, format="application/rdf+xml")
	return grph

