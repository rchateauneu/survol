#!/usr/bin/python

# The goal of this test is to detect global variables from a Python script.
# Specifically, we want to extract predicates used to create RDF triple.
# If we have this information, we know which kind of predicates a script
# might generate, without running it.
# When running a SPARQL server on a Survol agent, it helps to deduce which scripts should be run,
# to create a triplestore as appropriate as possible for a given SPARQL query..

# https://stackoverflow.com/questions/33160744/detect-all-global-variables-within-a-python-function

# This is for creating a SPARQL server.
# There are two different types of SPARQL server that Survol runs:
# (1) A SPARQL server which translates queries into WQL queries running on top
# of a WMI server or a WBEM server:
# - WQL cannot join tables.
# - It can be very slow.
# - It does not use RDF.
# - WQL can make queries on any field.
# (2) A SPARQL server which runs Survol Python providers on demand,
# based on the resources (predicates and rdfs:type) instantiated in the query.
# - There is no query language
# - Data can be accumulated in a RDF triplestore.
# - There should not be performance problem.
#
# This focuses on case (2).

import sys
import dis
import types
import importlib

import rdflib.namespace

GLOBAL_OPS = dis.opmap["LOAD_GLOBAL"], dis.opmap["STORE_GLOBAL"]
EXTENDED_ARG = dis.opmap["EXTENDED_ARG"]
LOAD_ATTR = dis.opmap["LOAD_ATTR"]

# TODO: Get functions call made within Survol and analyses them recursively,
# TODO: but only if they are in source_types.
def GetGlobalVariables(func,verbose):
    """This returns the global variables used in a function"""

    if verbose:
        print(dis.dis(func))

    func = getattr(func, "im_func", func)
    code = func.func_code
    names = code.co_names

    op_codes = (ord(c) for c in code.co_code)
    glob_classes = set()
    glob_namespaces = set()
    glob_destination = None
    extarg = 0

    glbl_nam = None
    glbl_obj = None
    for cod in op_codes:
        if cod in GLOBAL_OPS:
            idx = next(op_codes) + next(op_codes) * 256 + extarg
            glbl_nam = names[idx]

            try:
                glbl_obj = func.func_globals[glbl_nam]
                #print("g=",glbl_obj,"tp=",type(glbl_obj))

                if isinstance( glbl_obj, rdflib.namespace.Namespace ):
                    # primns = "http://primhillcomputers.com/survol"
                    # pc = lib_kbase.MakeNamespace(primns)
                    # ('g=', Namespace(u'http://primhillcomputers.com/survol'), 'tp=', <class 'rdflib.namespace.Namespace'>)
                    # 'pc.property_open_file'
                    glbl_nam = str(glbl_obj)
                    glob_destination = glob_namespaces
                    modu_delim = "#"
                elif isinstance( glbl_obj, types.ModuleType ):
                    # We are only interested by CIM class types as defined in directory sources_types.
                    # TODO: Possibly check if WMI class ?
                    glbl_nam = glbl_obj.__package__
                    glob_destination = glob_classes
                    modu_delim = "."
                else:
                    glbl_nam = None
                    glob_destination = None
            except:
                glbl_nam = None
                glbl_obj = None
        elif cod == EXTENDED_ARG:
            extarg = (next(op_codes) + next(op_codes) * 256) * 65536
            continue
        elif cod == LOAD_ATTR:
            idx = next(op_codes) + next(op_codes) * 256 + extarg
            attr = names[idx]
            if glbl_nam:
                glbl_nam += modu_delim + attr
                modu_delim = "."
        else:
            if glbl_nam:
                glob_destination.add(glbl_nam)
                glbl_nam = None
                glob_destination = None
            if cod >= dis.HAVE_ARGUMENT:
                next(op_codes)
                next(op_codes)

        extarg = 0

    return list(glob_classes), list(glob_namespaces)

# See lib_util.GetScriptModule(currentModule, fil)
def GetScriptModule(currentModule, fil):
    fileBaseName = fil[:-3] # Without the ".py" extension.

    if sys.version_info >= (3, ):
        if currentModule:
            importedMod = importlib.import_module(currentModule + "." + fileBaseName)
        else:
            importedMod = importlib.import_module(fileBaseName)
    else:
        if currentModule:
            importedMod = importlib.import_module("." + fileBaseName, currentModule )
        else:
            importedMod = importlib.import_module(fileBaseName)
    return importedMod

def AnalyseScript(currentModule, fil):
    print(currentModule,fil)
    """This receives a script and its directory, imports it and returns the global variables"""
    importedMod = GetScriptModule(currentModule, fil)

    #print(dis.dis(importedMod.Main))
    print( GetGlobalVariables(importedMod.Main,True) )

# 49     >>  314 LOAD_GLOBAL              0 (lib_common)
#            317 LOAD_ATTR               10 (gUriGen)
#            320 LOAD_ATTR               21 (FileUri)
#
#            344 LOAD_GLOBAL             23 (pc)
#            347 LOAD_ATTR               24 (property_open_file)
#
# 33         149 LOAD_GLOBAL              8 (CIM_Process)
#            152 LOAD_ATTR               12 (AddInfo)

# Very simplistic import of a script.
dir_code_base = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol"
sys.path.append(dir_code_base)

lstScripts = [
    # ['sources_types.CIM_Process.PsutilGetProcObj', 'sources_types.CIM_Process.PsutilProcConnections', 'sources_types.addr.PsutilAddSocketToGraph']
    ("sources_types.CIM_Process","process_connections.py"),
    # ['http://primhillcomputers.com/survol#property_open_file', 'sources_types.CIM_Process.AddInfo', 'sources_types.CIM_Process.PsutilGetProcObj', 'sources_types.CIM_Process.PsutilProcOpenFiles']
    ("sources_types.CIM_Process","process_open_files.py"),
    ("sources_types.CIM_DataFile","elftools_parse_symbols.py"),
    ("sources_types.Databases","oracle_tnsnames.py"),
    ("sources_types.CIM_DiskPartition","partition_diskusage.py"),
    ("sources_types.CIM_DataFile.portable_executable","pefile_information.py"),
]

for oneScript in lstScripts:
    try:
        AnalyseScript(oneScript[0],oneScript[1])
    except Exception as exc:
        print(exc)


# AnalyseScript("sources_types.CIM_Process","process_connections.py")



# ['importlib', '__builtin__', 'sys', 'types', 'dis']
# print(list(imports()))
# Problems with this approach:
# - It is a bit clunky.
# - Does not work with dynamic properties (But what would ?)
# - Does not work with Cython and possibly other implementations.
# - It is not supported by the standard.
