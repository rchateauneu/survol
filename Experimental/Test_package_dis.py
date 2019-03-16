# https://stackoverflow.com/questions/33160744/detect-all-global-variables-within-a-python-function

# This is for creating a SPARQL server.
# There are two diffeernt types of SPARQL server that Survol runs:
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


def GetGlobalVariables(func):
    GLOBAL_OPS = dis.opmap["LOAD_GLOBAL"], dis.opmap["STORE_GLOBAL"]
    EXTENDED_ARG = dis.opmap["EXTENDED_ARG"]
    LOAD_ATTR = dis.opmap["LOAD_ATTR"]

    func = getattr(func, "im_func", func)
    code = func.func_code
    names = code.co_names

    op_codes = (ord(c) for c in code.co_code)
    globs = set()
    extarg = 0

    glbl_nam = None
    for c in op_codes:
        if c in GLOBAL_OPS:
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
                    modu_delim = "#"
                elif isinstance( glbl_obj, types.ModuleType ):
                    glbl_nam = glbl_obj.__package__
                    modu_delim = "."
                else:
                    glbl_nam = None
            except:
                glbl_nam = None
                pass
        elif c == EXTENDED_ARG:
            extarg = (next(op_codes) + next(op_codes) * 256) * 65536
            continue
        elif c == LOAD_ATTR:
            idx = next(op_codes) + next(op_codes) * 256 + extarg
            attr = names[idx]
            if glbl_nam:
                glbl_nam += modu_delim + attr
                modu_delim = "."
        elif c >= dis.HAVE_ARGUMENT:
            if glbl_nam:
                globs.add(glbl_nam)
                glbl_nam = None
            next(op_codes)
            next(op_codes)
        else:
            if glbl_nam:
                globs.add(glbl_nam)
                glbl_nam = None

        extarg = 0

    return sorted(globs)

# See lib_util.GetScriptModule(currentModule, fil)
def AnalyseScript(currentModule, fil):

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

    #print(dis.dis(importedMod.Main))
    print( GetGlobalVariables(importedMod.Main) )
    #print(dir(importedMod))
    #print(dir(importedMod.__package__))
    # ModulesFrom(currentModule)

def ModulesFrom(currentModule):

    importedMod = importlib.import_module(currentModule)
    print(currentModule,"dir(importedMod):",dir(importedMod))
    print(dis.dis(importedMod))


    # 49     >>  314 LOAD_GLOBAL              0 (lib_common)
    #            317 LOAD_ATTR               10 (gUriGen)
    #            320 LOAD_ATTR               21 (FileUri)
    #
    #            344 LOAD_GLOBAL             23 (pc)
    #            347 LOAD_ATTR               24 (property_open_file)
    #
    # 33         149 LOAD_GLOBAL              8 (CIM_Process)
    #            152 LOAD_ATTR               12 (AddInfo)

    # ('lib_common', 'CgiEnv', 'False', 'int', 'GetId', 'bool', 'GetParameters', 'GetGraph', 'CIM_Process', 'PsutilGetProcObj', 'gUriGen', 'PidUri', 'AddInfo', 'str', 'PsutilProcOpenFiles', 'Exception', 'sys', 'exc_info', 'ErrorMessageHtml', 'MeaninglessFile', 'path', 'FileUri', 'add', 'pc', 'property_open_file', 'OutCgiRdf')
    # print(importedMod.Main.__code__.co_names)

# Very simplistic import of a script.
dir_code_base = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol"
sys.path.append(dir_code_base)


# ['CIM_Process', 'Exception', 'False', 'bool', 'int', 'lib_common', 'pc', 'str', 'sys']
AnalyseScript("sources_types.CIM_Process","process_connections.py")
AnalyseScript("sources_types.CIM_Process","process_open_files.py")


# ['importlib', '__builtin__', 'sys', 'types', 'dis']
# print(list(imports()))
# Problems with this approach:
# - It is a bit clunky.
# - Does not work with dynamic properties (But what would ?)
# - Does not work with Cython and possibly other implementations.
# - It is not supported by the standard.
