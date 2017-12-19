# Used for:
# - Scanning bookmarks to open them all, for testing.
# - When printing, gets descriptions associated to URLs.

text = "".join( file.readlines()[6:] )
# The format of bookmark files is not XML as some closing tags are missing.
# We repair the document by removing the opening tags.
text = text.replace("<DT>","").replace("<p>","").replace("<H3 FOLDED ","<H3 ")

# The XML parser does not link HTML entities in URLs.
text = text.replace("&","&amp;")
# Ca marche pas !!
# text = re.sub("&([^a][^m][^p])","&amp;\1",text)

root = xml.etree.ElementTree.fromstring(text)
for child in root:
	if child.tag == "H3":
    	sys.stderr.write( "%s\n" % child.text )
        for x in child.iter("A"):
        	sys.stderr.write( "%s\n" % (x.text))
            for aK in x.keys():
            	sys.stderr.write( "    %s %s\n" % (aK, x.get(aK)))