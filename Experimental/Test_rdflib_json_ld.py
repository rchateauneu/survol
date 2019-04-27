import rdflib

grph = rdflib.Graph()
result = grph.parse("http://www.w3.org/People/Berners-Lee/card")

print("graph has %s statements." % len(grph))
# prints graph has 79 statements.

s = grph.serialize(format='json-ld')

print(s)