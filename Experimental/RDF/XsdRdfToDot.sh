#!/bin/bash

# http://stackoverflow.com/questions/7014716/generate-a-dot-file-from-a-rdf-file

<xsl:for-each select="whateverThePathIs/person">
<xsl:if test="(./j:Gender &eq; 'Female')">
# Output a node for a Female
</xsl:if>
<xsl:if test="(./j:Gender &eq; 'Male')">
# Output a node for a Male
</xsl:if>
</xsl:for-each>


# http://plindenbaum.blogspot.co.uk/2010/02/another-tiny-tool-rdf-to-dot.html

xsltproc --html linkedin2foaf.xsl http://www.linkedin.com/in/lindenbaum |\
java -jar rdf2dot.jar |\
dot -Tsvg |\
java -jar svg2canvas.jar > file.html 


# http://en.wikibooks.org/wiki/XQuery/Graphing_from_RDF

