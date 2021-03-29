import os
import sys
import collections
import logging

import xml.etree.cElementTree

import lib_uris
import lib_common
import lib_util
from lib_properties import pc


file_extensions_dox = [
    "c", "cc", "cxx", "cpp", "c++", "java",
    "ii", "ixx", "ipp", "i++", "inl", "idl", "ddl", "odl",
    "h", "hh", "hxx", "hpp", "h++", "cs", "d", "php",
    "php4", "php5", "phtml", "inc", "m", "markdown", "md", "mm",
    "dox", "py", "f90", "f", "for", "tcl", "vhd", "vhdl", "ucf", "qsf", "as", "js",
]


def Usable(entity_type, entity_ids_arr):
    """This works for directories and code files too, depending on their extension."""
    if not lib_util.UsableWindows(entity_type, entity_ids_arr):
        return False

    path_nam = entity_ids_arr[0]

    if os.path.isdir(path_nam):
        return True

    filename, file_extension = os.path.splitext(path_nam)
    file_ext = file_extension[1:].lower()

    return file_ext in file_extensions_dox


def _generate_to_output_dir(out_dir):
    # http://stackoverflow.com/questions/651794/whats-the-best-way-to-initialize-a-dict-of-dicts-in-python
    def makehash():
        return collections.defaultdict(makehash)

    objects_by_location = makehash()

    location_file = "IMPOSSIBLE_LOCATION"
    member_definition = "IMPOSSIBLE_DEFINITION"
    for dir_name, subdir_list, file_list in os.walk(out_dir):
        for fname in file_list:
            xml_path = dir_name + "/" + fname
            try:
                for event, elem in xml.etree.cElementTree.iterparse(xml_path, events=("start", "end")):
                    if event == "start":
                        if elem.tag == "compounddef":
                            compounddef_kind = elem.attrib["kind"]
                        elif elem.tag == "compoundname":
                            compound_name = elem.text
                        elif elem.tag == "location":
                            location_file = elem.attrib["file"]
                        elif elem.tag == "sectiondef":
                            section_kind = elem.attrib["kind"]
                        elif elem.tag == "memberdef":
                            member_kind = elem.attrib["kind"]
                            member_static = elem.attrib["static"]
                            list_types = []
                        elif elem.tag == "templateparamlist":
                            member_kind = None
                        elif elem.tag == "name":
                            member_name = elem.text
                        elif elem.tag == "definition":
                            member_definition = elem.text
                        elif elem.tag == "type":
                            # Can be the return type of the function or one of its arguments, or the variable type.
                            # But this could contain other tags:
                            # "SafePtr< <ref refid="class_s_t_r_s_index_rule_defaults_1_1_i_data" kindref="compound">STRSIndexRuleDefaults::IData</ref> >"
                            # instead of "SafePtr< STRSIndexRuleDefaults::IData >"
                            # https://docs.python.org/2/library/xml.etree.elementtree.html
                            if member_kind:
                                # Only types list defined in "memberdef"
                                list_types.append("".join(elem.itertext()))

                    elif event == "end":
                        if elem.tag == "memberdef":
                            if member_kind == "function" and \
                                    (member_name[0] == '~' or member_name.startswith(
                                        "operator") or member_name == compound_name):
                                # No destructor or operator.
                                # TODO: Maybe constructor, depending on arguments ?
                                pass
                            elif member_kind == "variable" and member_static == "no":
                                # Only static members.
                                # TODO: Maybe members whose type is a class ? Points somewhere ?
                                pass
                            elif member_kind in ["typedef", "friend", "enum", "define"]:
                                pass
                            else:
                                if member_definition is None:
                                    member_definition= member_name

                                objects_by_location[location_file][compounddef_kind][compound_name][member_kind][member_definition] = list_types
            except Exception as exc:
                logging.warning("Caught:%s", str(exc))

    return objects_by_location


def _display_def(grph, node_file, location_file, sym_def, param_explode_classes):
    node_variable = lib_uris.gUriGen.SymbolUri(sym_def, location_file)
    if node_file:
        grph.add((node_file, pc.property_member, node_variable))
    return


def CreateObjs(grph, root_node, directory_name, objects_by_location, param_explode_classes):
    logging.debug("directoryName=%s num=%d", directory_name, len(objects_by_location))

    for location_file, v1 in lib_util.six_iteritems(objects_by_location):
        logging.debug("location_file=%s", location_file)

        node_file = lib_uris.gUriGen.FileUri(location_file)
        grph.add((root_node, pc.property_directory, node_file))

        for compounddef_kind, v2 in v1.items():
            for compound_name, v3 in v2.items():
                for member_kind, v4 in v3.items():
                    for member_definition, list_types in v4.items():
                        if member_kind == "function":
                            if len(list_types) > 1:
                                concat_types = ",".join(list_types[1:])
                            else:
                                concat_types = ""
                            func_name = member_definition + "(" + concat_types + ")"
                            _display_def(grph, node_file, location_file, func_name, param_explode_classes)
                        elif member_kind == "variable":
                            _display_def(grph, node_file, location_file, member_definition, param_explode_classes)
    return


_my_doxyfile = """
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


def _run_doxy(doxy_out_dir, doxyINPUT, is_doxy_recursive):
    """This runs the command "doxygen" on an input and writes the ouput XML files to a temporary directory. """
    doxy_file_patterns = " ".join("*.%s" % fil_ext for fil_ext in file_extensions_dox)

    # TODO: Create a tmp dir just for this purpose.
    fil_co = _my_doxyfile % (doxy_out_dir, doxyINPUT, doxy_file_patterns, is_doxy_recursive)

    # This is the input file to Doxygen.
    tmp_doxyfile_obj = lib_util.TmpFile("survol_doxygen_config")
    doxynam = tmp_doxyfile_obj.Name
    doxyfi = open(doxynam, "w")
    doxyfi.write(fil_co)
    doxyfi.close()

    # https://www.stack.nl/~dimitri/doxygen/manual/customize.html

    doxygen_command = ["doxygen", doxynam]

    # TODO: Use lib_common.SubProcPOpen
    ret = lib_common.SubProcCall(doxygen_command)
    logging.debug("doxy_out_dir=%s", doxy_out_dir)


def DoxygenMain(param_recursive_exploration, file_param):
    tmp_dir_obj = lib_util.TmpFile(prefix=None, suffix=None, subdir="survol_doxygen_xml")

    doxy_output_directory = tmp_dir_obj.TmpDirToDel

    if param_recursive_exploration:
        doxy_recursive = "YES"
    else:
        doxy_recursive = "NO"

    try:
        _run_doxy(doxy_output_directory, file_param, doxy_recursive)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Doxygen: %s\n" % str(exc))

    doxy_result_dir = doxy_output_directory + "/xml"
    objects_by_location = _generate_to_output_dir(doxy_result_dir)

    # At this stage, the temporary directory will be removed.
    return objects_by_location

