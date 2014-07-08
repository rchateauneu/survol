
// This is called asynchronously when the list of SLP urls arrives.
function FillFavoritesUrlsTable()
{
}

var dynCtnt = "";

// Recursive function to transform the bookmarks coming from cgi script, into html.
function JsonToTable(data)
{
	/* Concatenates a string instead of writing to the document
	   because it would cleanup this document first, including
	   all the HTML code written into it. */
	dynCtnt += '<table border=1>';

	$.each(
		data,
		function (i, fb)
		{
			if( ( typeof(fb.children) == "undefined" ) && ( typeof(fb.uri) == "undefined" ) )
			{
				return;
			}

			/*
			   i contains an index.
			   The fields dateAdded and lastModified can also be used
			 */
			dynCtnt += '<tr>';

			if( typeof(fb.children) == "object" )
			{
				// Maybe the content is empty. Then it will be ugly.
				dynCtnt += '<td></td>' 
				dynCtnt += '<td><i>' + fb.title + '</i></td>';
				dynCtnt += '<td>';
				JsonToTable(fb.children);
				dynCtnt += '</td>';
			}
			else
			{
				dynCtnt += '<td><input type="checkbox" name="' + fb.title + '" value="' + fb.uri + '"></td>' 
				dynCtnt += '<td>' + fb.title + '</td>';
				dynCtnt += '<td>' + fb.uri + '</td>';
			}

			dynCtnt += '</tr>';

		}
	);
	dynCtnt += '</table>';
}

/* Apparently it is executed in a sub-thread */
/* Add a display parameter maybe */
function ProcessBookmarks(data)
{
	/*
	result = JSON.stringify(data);
	alert("r="+result);
	*/
	dynCtnt += '<br>';
	JsonToTable(data.children);
	$("#DynContent").html(dynCtnt);
}

/*
Intentionnellement, on n’utilise que des packages standard et on propose le choix.

http://stackoverflow.com/questions/7014716/generate-a-dot-file-from-a-rdf-file

Peut-etre certains traitements specifiques pour certaines entites:
xslt is my preferred way to create graphviz files from xml. For you, the key part might look like this...
<xsl:for-each select="whateverThePathIs/person">
<xsl:if test="(./j:Gender &eq; 'Female')">

# Output a node for a Female
</xsl:if>
<xsl:if test="(./j:Gender &eq; 'Male')">
# Output a node for a Male
</xsl:if>
</xsl:for-each>

RDF-to-Dot
http://plindenbaum.blogspot.co.uk/2010/02/another-tiny-tool-rdf-to-dot.html
Ca utilise du Java:

xsltproc --html linkedin2foaf.xsl http://www.linkedin.com/in/lindenbaum |\
       java -jar rdf2dot.jar |\
       dot -Tsvg |\
       java -jar svg2canvas.jar > file.html

https://code.google.com/p/jenatools/source/browse/trunk/jenatools-package/src/main/java/com/barraquand/labs/jenatools/RDF2DOT.java

Essayser vraiment de l’utiliser et de le builder a la place de notre script en Python.

Fabriquer le reseau des appels avec la relation “Fonction X appelle fonction Y »
Alleger avec la relation « class X appelle class Y » et « fichier X appelle fichier Y »
On peut l’extraire a la volee avec strace.
Ou bien utiliser un parseur.
Ce qui est important est de réduire la taille du graphe.

Idem pour l’arbres des modules : On essaie de rassembler les vertices dans des classes.

http://www.stack.nl/~dimitri/doxygen/manual/customize.html#xmlgenerator
                                                  GENERATE_XML to YES
Fabriquer le fichier de config pour doxygen.
Pour l’outil, on lui fournit un directory ou se trouve un makefile. Ou bien un doxyfile.
L’important est le parseur.
Et aussi la possiblite d’aggreger.
Memes noms de nœuds que dans strace.

Traduire rdf en viz: http://www.developpez.net/forums/d1118596/webmasters-developpement-web/web-semantique/ontologies/traduire-rdf-dot/
owlviz est un plugin de protégé.


 *
 *
 */
