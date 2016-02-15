#!/usr/bin/python

import sys
import rdflib
import urllib
import array
import netifaces

from optparse import OptionParser
from rdflib import Graph

grph = Graph()

def main():
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)
	parser.add_option("-v", "--verbose", action="store_true", dest="verbose")

	parser.add_option("-o", "--output", type="string",
                  help="Output file",
                  dest="outFil", default="dflt_merge_result.rdf")

	(options, args) = parser.parse_args()
	if options.verbose:
		print "Writing into %s..." % options.outFil
	#if len(args) != 1:
	#	parser.error("Incorrect number of arguments")

	cnt = 1
	for urlfil in args:
		tmpfil = "tmp_" + str(cnt) + ".tmp"
		print "Merging " + urlfil + " into " + tmpfil
		urllib.urlretrieve (urlfil, tmpfil)
		grph.parse(tmpfil)
		cnt=cnt+1

	# TODO: Output file as a parameter.
	outRdfFil = open(options.outFil, 'w')
	outRdfFil.write( grph.serialize(format="xml") )
	outRdfFil.close()
	print "Merged into " + options.outFil

if __name__ == "__main__":
    main()

