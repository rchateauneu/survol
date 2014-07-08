
import socket
import rdflib
import sys
import os
import re

pc = rdflib.Namespace("http://primhillcomputers.com/ontologies")

# All the properties for creating RDF triples.
pc.property_pid = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/pid')
pc.property_ppid = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/ppid')
pc.property_host = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/host')
pc.property_hostname = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/hostname')
pc.property_interface = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/interface')
pc.property_socket_addr = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/socket_addr')
pc.property_socket_port = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/socket_port')
pc.property_has_socket_end = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/has_socket_end')
pc.property_socket_end = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/socket_end')
pc.property_ip_addr = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/ip_addr')
pc.property_open_file = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/open_file')
pc.property_memmap = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/memmap')
pc.property_mysql_id = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/mysql_id')
pc.property_cpu = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/cpu')
pc.property_virt = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/virt')
pc.property_module_dep = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/module_dep')
pc.property_symbol_defined = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/symbol_defined')
pc.property_symbol_undefined = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/symbol_undefined')
pc.property_library_depends = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/library_depends')
pc.property_symlink = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/symlink')
pc.property_mount = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/mount')

def HostName():
	if socket.gethostname().find('.')>=0:
    		name=socket.gethostname()
	else:
    		name=socket.gethostbyaddr(socket.gethostname())[0]
	return name
hostName = HostName()

nodeMachine = rdflib.term.URIRef('urn://' + hostName )

# Must find a way to hard-decode this.
def UriRoot():

	# Default values for ease of testing, so CGI scripts can be run as is from command line..
	try:
		remote_addr = os.environ['REMOTE_ADDR']
	except KeyError:
		remote_addr = "127.0.0.1"
	
	try:
		server_port = os.environ['SERVER_PORT']
	except KeyError:
		server_port = "8080"

	# TODO: REMOVE THIS HARD-CODE !!!!!
	# return 'http://' + os.environ['REMOTE_ADDR'] + ':' + os.environ['SERVER_PORT'] + os.path.dirname(os.environ['SCRIPT_NAME'])
	# return "http://127.0.0.1:2468/htbin"
	return 'http://' + remote_addr + ':' + server_port + "/~rchateau/RevPython"

# Curieusement, quand on clique le lien dans le fichier SVG,
# ca ouvre une nouvelle fenetre.
# Ce n'est pas forcement genant, mais on voudrait:
# - Ouvrir un pop-up de facon a choisir une source correspondant a l'entite.
# - Aller chercher au SVG et l'injecter au SVG courant, le fusionner a ce qu'on a deja.
# Ca suppose qu'on puisse manipuler du SVG comme on le fait avec le RDF.
# Pourquoi pas, mais il faudrait donner a chaque object SVG un id qui pointe sur
# le RDF, fabriquer un nouveau SVG, mettre a jour les coordonnees des id
# existants etc... On en est tres loin.
# Pour le moment, ouvrir une nouvelle page, c'est suffisant.

def EntityUri(entity_type,entity_id):
	return rdflib.term.URIRef( UriRoot() + '/entity_list.py?type=' + entity_type + '&id=' + entity_id)

# TODO: Must add the hostname in the id !!!
# Or is it implicit with UriRoot ??
def PidUri(pid):
	return EntityUri('process',str(pid))

# TODO: Must add the hostname in the id !!!
# Or is it implicit with UriRoot ??
def SharedLibUri(soname):
	return EntityUri('so',soname)

# For a hard-disk. Used to display the mount point,
# and also the IO performance.
def DiskPartitionUri(disk_name):
	return EntityUri('partition',disk_name)

# Purely abstract, because a symbol can be defined in several libraries.
# Its use depend on the behaviour of the dynamic linker if it is defined several
# times in the same binary.
# HOWEVER, SHOULD WE ADD THE MACHINE ? MAYBE NOT...
def SymbolUri(symbol_name):
	return EntityUri('symbol',symbol_name)

# This must be a complete path name.
def FileUri(path):
	# Otherwise Jena lib will throw.
	cleanpath = path.strip(' ')
	# It must starts with a slash.
	if( ( len(cleanpath) > 0 ) and (cleanpath[0] != '/') ):
		cleanpath = '/' + cleanpath

	# return rdflib.term.URIRef('file://' + hostName + path )
	return EntityUri('file',path)

# Here, should create a connection to the hostname.
def AnonymousPidNode(host):
	return rdflib.BNode()

# This creates a node for a socket, so later it can be merged
# with the same socket 
def AddrUri(addr,port):
	return rdflib.term.URIRef('urn://' + addr + ':' + str(port) )

# This applies to Linux and KDE only. Temporary.
uselessProcesses = [ 'bash', 'gvim', 'konsole' ]

def UselessProc(proc):
	procName = proc.name
	return procName in uselessProcesses

# Used by all CGI scripts when they have finished adding triples to the current RDF graph.
# This just writes a RDF document which can be used as-is by browser,
# or by another scripts which will process this RDF as input, for example when merging RDF data.
# Consider adding reformatting when the output is a browser ... if this can be detected !!
# It is probably possible with the CGI environment variable HTTP_USER_AGENT.
# Also, the display preference could be stored with the Python library cookielib.
def OutCgiRdf(grph):
	print("Content-type: text/rdf")
	print("")
	# Format support can be extended with plugins,
	# but 'xml', 'n3', 'nt', 'trix', 'rdfa' are built in.
	print( grph.serialize(format="xml") )

# By the way, when calling a RDF source, we should check the type of the
# MIME document and if this is not RDF, the assumes it's an error 
# which must be displayed.
def ErrorMessageHtml(message):
	print("Content-Type: text/html")
	print("")
	print("<html>")
	print("<head>")
	print("</head>")
	print("<title>")
	print("Process=" + str(os.getpid()) )
	print("</title>")
	print("<body>")
	# On Linux it says: "OSError: [Errno 2] No such file or directory"
	if sys.platform == 'win32':
		print("Login:" + os.getlogin() + "<br>")
	print("Cwd:" + os.getcwd() + "<br>")
	print("ERROR MESSAGE:" + message)
	print("</body>")
	print("</html>")
	sys.exit(0)

# TODO: Should be portable.
def TmpDir():
	return "/tmp"


################################################################################

# Used when displaying all files open by a process: There are many of them,
# so the useless junk could maybe be eliminated.
# TODO: This should be portable.
def MeaningLessFile(path):
	# Some files are not interesting at all.
	if ( path == "/home/rchateau/.xsession-errors" ):
		return 1

	# We could also check if this is really a shared library.
	# file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
	if path.endswith(".so"):
		return 1

	# Not sure about "M" and "I". Also: Should precompile regexes.
	if re.match( r'/lib/.*\.so\..*', path, re.M|re.I):
		return 1

	if re.match( r'/usr/lib/.*\.so\..*', path, re.M|re.I):
		return 1

	if re.match( r'/usr/share/locale/.*', path, re.M|re.I):
		return 1

	if re.match( r'/usr/share/fonts/.*', path, re.M|re.I):
		return 1

	if re.match( r'/etc/locale/.*', path, re.M|re.I):
		return 1

	if re.match( r'/var/cache/fontconfig/.*', path, re.M|re.I):
		return 1

	if re.match( r'/usr/lib/jvm/.*', path, re.M|re.I):
		return 1

	return 0

################################################################################

