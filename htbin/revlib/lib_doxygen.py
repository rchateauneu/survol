import os
import sys
import six
import rdflib
import subprocess
import collections
import lib_common
import lib_util
from lib_properties import pc
import xml.etree.cElementTree


fileExtensionsDox = [
	"c","cc","cxx","cpp","c++","java",
	"ii","ixx","ipp","i++","inl","idl","ddl","odl",
	"h","hh","hxx","hpp","h++","cs","d","php",
	"php4","php5","phtml","inc","m","markdown","md","mm",
	"dox","py","f90","f","for","tcl","vhd","vhdl","ucf","qsf","as","js",
]

# This works for directories and code files too, depending on their extension.
def Usable(entity_type, entity_ids_arr):
	if not lib_util.UsableWindows(entity_type, entity_ids_arr):
		return False

	pathNam = entity_ids_arr[0]

	if os.path.isdir(pathNam):
		return True

	filename, file_extension = os.path.splitext(pathNam)
	fileExt = file_extension[1:].lower()

	return fileExt in fileExtensionsDox

def DoTheStuff(outDir):
	# http://stackoverflow.com/questions/651794/whats-the-best-way-to-initialize-a-dict-of-dicts-in-python
	def makehash():
		return collections.defaultdict(makehash)

	objectsByLocation = makehash()

	locationFile = "IMPOSSIBLE_LOCATION"
	memberDefinition = "IMPOSSIBLE_DEFINITION"
	for dirName, subdirList, fileList in os.walk(outDir):
		for fname in fileList:
			#sys.stderr.write("fname=%s\n" % fname)
			xmlPath = dirName + "/" + fname
			try:
				for event, elem in xml.etree.cElementTree.iterparse(xmlPath, events=("start", "end")):
					#sys.stderr.write("elem.tag=%s\n" % elem.tag)
					#sys.stderr.write("elem.text=%s\n" % elem.text)

					if event == "start":
						if elem.tag == "compounddef":
							compounddefKind = elem.attrib["kind"]
						elif elem.tag == "compoundname":
							compoundName = elem.text
						elif elem.tag == "location":
							locationFile = elem.attrib["file"]
						elif elem.tag == "sectiondef":
							sectionKind = elem.attrib["kind"]
						elif elem.tag == "memberdef":
							memberKind = elem.attrib["kind"]
							memberStatic = elem.attrib["static"]
							listTypes = []
						elif elem.tag == "templateparamlist":
							memberKind = None
						elif elem.tag == "name":
							memberName = elem.text
						elif elem.tag == "definition":
							memberDefinition = elem.text
						elif elem.tag == "type":
							# Can be the return type of the function or one of its arguments, or the variable type.
							# But this could contain other tags:
							# "SafePtr< <ref refid="class_s_t_r_s_index_rule_defaults_1_1_i_data" kindref="compound">STRSIndexRuleDefaults::IData</ref> >"
							# instead of "SafePtr< STRSIndexRuleDefaults::IData >"
							# https://docs.python.org/2/library/xml.etree.elementtree.html
							if memberKind:
								# Only types list defined in "memberdef"
								listTypes.append("".join(elem.itertext()))

					elif event == "end":
						if elem.tag == "memberdef":
							if memberKind == "function" and \
									(memberName[0] == '~' or memberName.startswith(
										"operator") or memberName == compoundName):
								# No destructor or operator.
								# TODO: Maybe constructor, depending on arguments ?
								pass
							elif memberKind == "variable" and memberStatic == "no":
								# Only static members.
								# TODO: Maybe members whose type is a class ? Points somewhere ?
								pass
							elif memberKind in ["typedef", "friend", "enum", "define"]:
								pass
							else:
								if memberDefinition is None:
									memberDefinition= memberName

								# TODO: A-t-n vraiment de compounddefKind][compoundName][memberKind]
								# TODO ... sachant qu on se donne la possibilite d exploser ou pas selon les classes ?
								objectsByLocation[locationFile][compounddefKind][compoundName][memberKind][memberDefinition] = listTypes
						# print(event)
						# print(elem.tag)
						# print(elem.tag)
						# break
			except Exception:
				exc = sys.exc_info()[1]
				sys.stderr.write("Caught:%s\n" % str(exc))

	return objectsByLocation

def DisplayDefinition(grph,nodeFile,locationFile,symDef,paramExplodeClasses):
	nodeVariable = lib_common.gUriGen.SymbolUri( symDef, locationFile )
	if nodeFile:
		grph.add( ( nodeFile, pc.property_member, nodeVariable ) )
	return

def CreateObjs(grph,rootNode,directoryName,objectsByLocation,paramExplodeClasses):
	sys.stderr.write("\n\n\n\directoryName=%s num=%d\n\n"%( directoryName, len(objectsByLocation)))

	for (locationFile, v1) in six.iteritems(objectsByLocation):
		sys.stderr.write("locationFile=%s\n"%locationFile)

		# TODO: Eventuellement exploser selon les sous-directorys
		nodeFile = lib_common.gUriGen.FileUri( locationFile )
		grph.add( ( rootNode, pc.property_directory, nodeFile ) )

		for (compounddefKind, v2) in v1.items():
			#sys.stderr.write("compounddefKind=%s\n"%compounddefKind)
			for (compoundName, v3) in v2.items():
				#sys.stderr.write("compoundName=%s\n"%compoundName)
				for (memberKind, v4) in v3.items():
					#sys.stderr.write("memberKind=%s\n"%memberKind)
					for (memberDefinition, listTypes) in v4.items():
						if memberKind == "function":
							if( len(listTypes) > 1 ):
								concatTypes = ",".join(listTypes[1:])
							else:
								concatTypes = ""
							# funcName = listTypes[0] + " " + memberName + "(" + concatTypes + ")"
							funcName = memberDefinition + "(" + concatTypes + ")"
							#nodeFunction = lib_common.gUriGen.SymbolUri( funcName, locationFile )
							#if nodeFile:
							#	grph.add( ( nodeFile, pc.property_member, nodeFunction ) )
							DisplayDefinition(grph,nodeFile,locationFile,funcName,paramExplodeClasses)
						elif memberKind == "variable":
							DisplayDefinition(grph,nodeFile,locationFile,memberDefinition,paramExplodeClasses)
							# nodeVariable = lib_common.gUriGen.SymbolUri( memberName, locationFile )
							#nodeVariable = lib_common.gUriGen.SymbolUri( memberDefinition, locationFile )
							#if nodeFile:
							#	grph.add( ( nodeFile, pc.property_member, nodeVariable ) )
	return


myDoxyfile = """
DOXYFILE_ENCODING      = UTF-8
PROJECT_NAME           = Survol
PROJECT_NUMBER         =
PROJECT_BRIEF          =
PROJECT_LOGO           =
OUTPUT_DIRECTORY       = %s
CREATE_SUBDIRS         = NO
OUTPUT_LANGUAGE        = English
BRIEF_MEMBER_DESC      = YES
REPEAT_BRIEF           = YES
# ABBREVIATE_BRIEF       = "The $name class"
ALWAYS_DETAILED_SEC    = NO
INLINE_INHERITED_MEMB  = NO
FULL_PATH_NAMES        = YES
STRIP_FROM_PATH        =
STRIP_FROM_INC_PATH    =
SHORT_NAMES            = NO
JAVADOC_AUTOBRIEF      = NO
QT_AUTOBRIEF           = NO
MULTILINE_CPP_IS_BRIEF = NO
INHERIT_DOCS           = NO
SEPARATE_MEMBER_PAGES  = NO
TAB_SIZE               = 4
ALIASES                =
TCL_SUBST              =
OPTIMIZE_OUTPUT_FOR_C  = NO
OPTIMIZE_OUTPUT_JAVA   = NO
OPTIMIZE_FOR_FORTRAN   = NO
OPTIMIZE_OUTPUT_VHDL   = NO
EXTENSION_MAPPING      =
MARKDOWN_SUPPORT       = YES
AUTOLINK_SUPPORT       = YES
BUILTIN_STL_SUPPORT    = NO
CPP_CLI_SUPPORT        = NO
SIP_SUPPORT            = NO
IDL_PROPERTY_SUPPORT   = YES
DISTRIBUTE_GROUP_DOC   = NO
SUBGROUPING            = YES
INLINE_GROUPED_CLASSES = NO
INLINE_SIMPLE_STRUCTS  = NO
TYPEDEF_HIDES_STRUCT   = NO
LOOKUP_CACHE_SIZE      = 0
EXTRACT_ALL            = YES
EXTRACT_PRIVATE        = NO
EXTRACT_PACKAGE        = NO
EXTRACT_STATIC         = YES
EXTRACT_LOCAL_CLASSES  = YES
EXTRACT_LOCAL_METHODS  = NO
EXTRACT_ANON_NSPACES   = NO
HIDE_UNDOC_MEMBERS     = NO
HIDE_UNDOC_CLASSES     = NO
HIDE_FRIEND_COMPOUNDS  = NO
HIDE_IN_BODY_DOCS      = NO
INTERNAL_DOCS          = NO
CASE_SENSE_NAMES       = NO
HIDE_SCOPE_NAMES       = NO
SHOW_INCLUDE_FILES     = YES
SHOW_GROUPED_MEMB_INC  = NO
FORCE_LOCAL_INCLUDES   = NO
INLINE_INFO            = NO
SORT_MEMBER_DOCS       = YES
SORT_BRIEF_DOCS        = NO
SORT_MEMBERS_CTORS_1ST = NO
SORT_GROUP_NAMES       = NO
SORT_BY_SCOPE_NAME     = NO
STRICT_PROTO_MATCHING  = NO
GENERATE_TODOLIST      = NO
GENERATE_TESTLIST      = NO
GENERATE_BUGLIST       = NO
GENERATE_DEPRECATEDLIST= NO
ENABLED_SECTIONS       =
MAX_INITIALIZER_LINES  = 30
SHOW_USED_FILES        = YES
SHOW_FILES             = YES
SHOW_NAMESPACES        = YES
FILE_VERSION_FILTER    =
LAYOUT_FILE            =
CITE_BIB_FILES         =
QUIET                  = YES
WARNINGS               = NO
WARN_IF_UNDOCUMENTED   = NO
WARN_IF_DOC_ERROR      = NO
WARN_NO_PARAMDOC       = NO
WARN_FORMAT            = "$file:$line: $text"
WARN_LOGFILE           =
INPUT                  = %s
INPUT_ENCODING         = UTF-8
FILE_PATTERNS          = %s
RECURSIVE              = %s
EXCLUDE                =
EXCLUDE_SYMLINKS       = NO
EXCLUDE_PATTERNS       =
EXCLUDE_SYMBOLS        =
EXAMPLE_PATH           =
EXAMPLE_PATTERNS       = *
EXAMPLE_RECURSIVE      = NO
IMAGE_PATH             =
INPUT_FILTER           =
FILTER_PATTERNS        =
FILTER_SOURCE_FILES    = NO
FILTER_SOURCE_PATTERNS =
USE_MDFILE_AS_MAINPAGE =
SOURCE_BROWSER         = NO
INLINE_SOURCES         = NO
STRIP_CODE_COMMENTS    = YES
REFERENCED_BY_RELATION = NO
REFERENCES_RELATION    = NO
REFERENCES_LINK_SOURCE = NO
SOURCE_TOOLTIPS        = YES
USE_HTAGS              = NO
VERBATIM_HEADERS       = NO
CLANG_ASSISTED_PARSING = NO
CLANG_OPTIONS          =
ALPHABETICAL_INDEX     = NO
COLS_IN_ALPHA_INDEX    = 5
IGNORE_PREFIX          =
GENERATE_HTML          = NO
HTML_OUTPUT            = html
HTML_FILE_EXTENSION    = .html
HTML_HEADER            =
HTML_FOOTER            =
HTML_STYLESHEET        =
HTML_EXTRA_STYLESHEET  =
HTML_EXTRA_FILES       =
HTML_COLORSTYLE_HUE    = 220
HTML_COLORSTYLE_SAT    = 100
HTML_COLORSTYLE_GAMMA  = 80
HTML_TIMESTAMP         = YES
HTML_DYNAMIC_SECTIONS  = NO
HTML_INDEX_NUM_ENTRIES = 100
GENERATE_DOCSET        = NO
DOCSET_FEEDNAME        = "Doxygen generated docs"
DOCSET_BUNDLE_ID       = org.doxygen.Project
DOCSET_PUBLISHER_ID    = org.doxygen.Publisher
DOCSET_PUBLISHER_NAME  = Publisher
GENERATE_HTMLHELP      = NO
CHM_FILE               =
HHC_LOCATION           =
GENERATE_CHI           = NO
CHM_INDEX_ENCODING     =
BINARY_TOC             = NO
TOC_EXPAND             = NO
GENERATE_QHP           = NO
QCH_FILE               =
QHP_NAMESPACE          = org.doxygen.Project
QHP_VIRTUAL_FOLDER     = doc
QHP_CUST_FILTER_NAME   =
QHP_CUST_FILTER_ATTRS  =
QHP_SECT_FILTER_ATTRS  =
QHG_LOCATION           =
GENERATE_ECLIPSEHELP   = NO
ECLIPSE_DOC_ID         = org.doxygen.Project
DISABLE_INDEX          = NO
GENERATE_TREEVIEW      = NO
ENUM_VALUES_PER_LINE   = 4
TREEVIEW_WIDTH         = 250
EXT_LINKS_IN_WINDOW    = NO
FORMULA_FONTSIZE       = 10
FORMULA_TRANSPARENT    = YES
USE_MATHJAX            = NO
MATHJAX_FORMAT         = HTML-CSS
MATHJAX_RELPATH        = http://cdn.mathjax.org/mathjax/latest
MATHJAX_EXTENSIONS     =
MATHJAX_CODEFILE       =
SEARCHENGINE           = YES
SERVER_BASED_SEARCH    = NO
EXTERNAL_SEARCH        = NO
SEARCHENGINE_URL       =
SEARCHDATA_FILE        = searchdata.xml
EXTERNAL_SEARCH_ID     =
EXTRA_SEARCH_MAPPINGS  =
GENERATE_LATEX         = NO
LATEX_OUTPUT           = latex
LATEX_CMD_NAME         = latex
MAKEINDEX_CMD_NAME     = makeindex
COMPACT_LATEX          = NO
PAPER_TYPE             = a4
EXTRA_PACKAGES         =
LATEX_HEADER           =
LATEX_FOOTER           =
LATEX_EXTRA_FILES      =
PDF_HYPERLINKS         = YES
USE_PDFLATEX           = YES
LATEX_BATCHMODE        = NO
LATEX_HIDE_INDICES     = NO
LATEX_SOURCE_CODE      = NO
LATEX_BIB_STYLE        = plain
GENERATE_RTF           = NO
RTF_OUTPUT             = rtf
COMPACT_RTF            = NO
RTF_HYPERLINKS         = NO
RTF_STYLESHEET_FILE    =
RTF_EXTENSIONS_FILE    =
GENERATE_MAN           = NO
MAN_OUTPUT             = man
MAN_EXTENSION          = .3
MAN_LINKS              = NO
GENERATE_XML           = YES
XML_OUTPUT             = xml
# XML_SCHEMA             =
# XML_DTD                =
XML_PROGRAMLISTING     = NO
GENERATE_DOCBOOK       = NO
DOCBOOK_OUTPUT         = docbook
GENERATE_AUTOGEN_DEF   = NO
GENERATE_PERLMOD       = NO
PERLMOD_LATEX          = NO
PERLMOD_PRETTY         = YES
PERLMOD_MAKEVAR_PREFIX =
ENABLE_PREPROCESSING   = YES
MACRO_EXPANSION        = NO
EXPAND_ONLY_PREDEF     = NO
SEARCH_INCLUDES        = NO
INCLUDE_PATH           =
INCLUDE_FILE_PATTERNS  =
PREDEFINED             =
EXPAND_AS_DEFINED      =
SKIP_FUNCTION_MACROS   = YES
TAGFILES               =
GENERATE_TAGFILE       =
ALLEXTERNALS           = NO
EXTERNAL_GROUPS        = YES
EXTERNAL_PAGES         = YES
PERL_PATH              = /usr/bin/perl
CLASS_DIAGRAMS         = NO
MSCGEN_PATH            =
DIA_PATH               =
HIDE_UNDOC_RELATIONS   = NO
HAVE_DOT               = NO
DOT_NUM_THREADS        = 0
DOT_FONTNAME           = Helvetica
DOT_FONTSIZE           = 10
DOT_FONTPATH           =
CLASS_GRAPH            = YES
COLLABORATION_GRAPH    = YES
GROUP_GRAPHS           = YES
UML_LOOK               = NO
UML_LIMIT_NUM_FIELDS   = 10
TEMPLATE_RELATIONS     = NO
INCLUDE_GRAPH          = YES
INCLUDED_BY_GRAPH      = YES
CALL_GRAPH             = NO
CALLER_GRAPH           = NO
GRAPHICAL_HIERARCHY    = YES
DIRECTORY_GRAPH        = YES
DOT_IMAGE_FORMAT       = png
INTERACTIVE_SVG        = NO
DOT_PATH               =
DOTFILE_DIRS           =
MSCFILE_DIRS           =
DIAFILE_DIRS           =
DOT_GRAPH_MAX_NODES    = 50
MAX_DOT_GRAPH_DEPTH    = 0
DOT_TRANSPARENT        = NO
DOT_MULTI_TARGETS      = NO
GENERATE_LEGEND        = YES
DOT_CLEANUP            = YES
"""


def RunDoxy(doxyOUTPUT_DIRECTORY, doxyINPUT, doxyRECURSIVE):

	doxyFILE_PATTERNS = " ".join( "*.%s" % filExt for filExt in fileExtensionsDox )

	# TODO: Create a tmp dir just for this purpose.
	filCo = myDoxyfile % (doxyOUTPUT_DIRECTORY, doxyINPUT, doxyFILE_PATTERNS, doxyRECURSIVE)

	tmpDoxyfileObj = lib_common.TmpFile("Doxygen")
	doxynam = tmpDoxyfileObj.Name
	doxyfi = open(doxynam, "w")
	doxyfi.write(filCo)
	doxyfi.close()


	# tmpDoxygenFil = lib_common.TmpFile("Doxygen","xml")
	# doxygen_out_filnam = tmpDoxygenFil.Name

	# https://www.stack.nl/~dimitri/doxygen/manual/customize.html

	doxygen_command = ["doxygen", doxynam]

	ret = subprocess.call(doxygen_command, stdout=sys.stderr, stderr=sys.stderr, shell=False)
	sys.stderr.write("doxyOUTPUT_DIRECTORY=%s\n" % (doxyOUTPUT_DIRECTORY))


def DoxygenMain(paramRecursiveExploration,fileParam):
	tmpDirObj = lib_common.TmpFile(prefix=None,suffix=None,subdir="DoxygenXml")

	doxyOUTPUT_DIRECTORY = tmpDirObj.TmpDirToDel

	if paramRecursiveExploration:
		doxyRECURSIVE = "YES"
	else:
		doxyRECURSIVE = "NO"

	try:
		RunDoxy(doxyOUTPUT_DIRECTORY, fileParam, doxyRECURSIVE)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Doxygen: %s\n"%( str(exc) ))

	doxyResultDir = doxyOUTPUT_DIRECTORY + "/xml"
	objectsByLocation = DoTheStuff(doxyResultDir)
	return objectsByLocation

