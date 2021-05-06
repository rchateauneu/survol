"""
Python package
"""

import os
import sys
import six
import logging
import importlib

import lib_common
import lib_uris
import lib_util
import lib_python
from lib_properties import pc

try:
    import modulefinder
except ImportError:
    pass


# TODO: Should do that only when executing ?? How to make the difference ??
prop_python_version = lib_common.MakeProp("Version")
prop_python_requires = lib_common.MakeProp("Requires")
prop_python_package = lib_common.MakeProp("Package")


def EntityOntology():
    return (["Id"],)


# TODO: Is the caption the best key ? Also: It should dependd on the Python version.
def MakeUri(package_key):
    return lib_uris.gUriGen.node_from_args("python/package", package_key)


def _fill_one_package(grph, node, good_pckg):
    """Display information about a Python package using what is returned by PIP."""

    # >>> dir(installed_packages[0])
    # ['PKG_INFO', '__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
    #  '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
    #  '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_dep_map', '_get_metadata', '_key', '_provider', '_relo
    # ad_version', '_version', '_warn_legacy_version', 'activate', 'as_requirement', 'check_version_conflict', 'clone', 'egg_name', 'extra
    # s', 'from_filename', 'from_location', 'get_entry_info', 'get_entry_map', 'has_version', 'hashcmp', 'insert_on', 'key', 'load_entry_p
    # oint', 'location', 'parsed_version', 'platform', 'precedence', 'project_name', 'py_version', 'requires', 'version']

    grph.add((node, prop_python_version, lib_util.NodeLiteral(good_pckg.version)))
    grph.add((node, lib_common.MakeProp("Platform"), lib_util.NodeLiteral(good_pckg.platform)))
    grph.add((node, lib_common.MakeProp("project_name"), lib_util.NodeLiteral(good_pckg.project_name)))

    # >>> pip.get_installed_distributions()[1].requires()
    # [Requirement.parse('distribute'), Requirement.parse('werkzeug'), Requirement.parse('mako')]
    # '_Requirement__hash', '__contains__','__doc__', '__eq__', '__hash__','__init__', '__module__', '__ne__',
    # '__repr__', '__str__', 'extras','hashCmp', 'key', 'marker_fn', 'parse','project_name', 'specifier', 'specs','unsafe_name'

    for sub_req in good_pckg.requires():
        sub_node = MakeUri(sub_req.key)
        # [('>=', '4.0.0')]+[]+[('>=','4.0')]+[]
        a_specs = sub_req.specs
        if a_specs:
            grph.add((sub_node, lib_common.MakeProp("Condition"), lib_util.NodeLiteral(str(a_specs))))
        grph.add((node, lib_common.MakeProp("requires"), sub_node))

    grph.add((node, lib_common.MakeProp("py_version"), lib_util.NodeLiteral(good_pckg.py_version)))
    grph.add((node, lib_common.MakeProp("precedence"), lib_util.NodeLiteral(good_pckg.precedence)))
    grph.add((node, lib_common.MakeProp("egg_name"), lib_util.NodeLiteral(good_pckg.egg_name())))

    # This might return location="c:\python27\lib\site-packages"
    clean_loca_dir = lib_util.standardized_file_path(good_pckg.location)
    node_location = lib_uris.gUriGen.DirectoryUri(clean_loca_dir)
    grph.add((node, lib_common.MakeProp("Location"), node_location))


# http://stackoverflow.com/questions/247770/retrieving-python-module-path
#import imp
#imp.find_module("os")
#It gives a tuple with the path in second position:
#(<open file '/usr/lib/python2.7/os.py', mode 'U' at 0x7f44528d7540>,
#'/usr/lib/python2.7/os.py',
#('.py', 'U', 1))


def _add_info_from_pip(grph, node, package_key):
    """Each entity can have such a file with its name as file name.
    Then in its file, by convention adds information to a node."""
    try:
        # TODO: What about several Python versions ?
        installed_packages = lib_python.PipGetInstalledDistributions()

        # TODO: Maybe the version should be part of the key.
        for pckg in installed_packages:
            if package_key == pckg.key:
                _fill_one_package(grph, node, pckg)
            else:
                for sub_req in pckg.requires():
                    if sub_req.key == package_key:
                        subNode = MakeUri( pckg.key )
                        # [('>=', '4.0.0')]+[]+[('>=','4.0')]+[]
                        a_specs = sub_req.specs
                        if a_specs:
                            # TODO: This should be displayed on the edge !!!
                            grph.add((
                                node,
                                lib_common.MakeProp("Condition " + pckg.key),
                                lib_util.NodeLiteral(str(a_specs))))
                        grph.add((subNode, prop_python_requires, node))
                        break

    except Exception as exc:
        grph.add((node, pc.property_information, lib_util.NodeLiteral(str(exc))))


def _add_info_from_import(grph, package_node, package_key):
    """Displays general information about the module."""
    try:
        the_module = importlib.import_module(package_key)
    except ImportError:
        lib_common.ErrorMessageHtml("Importing %s: Error %s" % (package_key, str(sys.exc_info())))

    try:
        init_fil_nam = the_module.__file__
        fil_node = lib_uris.gUriGen.FileUri(init_fil_nam)
        grph.add((package_node, prop_python_package, fil_node))
    except AttributeError:
        pass

    try:
        txt_doc = the_module.__doc__
        if txt_doc:
            txt_doc = txt_doc.strip()
            grph.add((package_node, pc.property_information, lib_util.NodeLiteral(txt_doc)))
    except AttributeError:
        pass

    props_package = {"Author": "__author__", "Version": "__version__"}

    for key_prop in props_package:
        val_prop = props_package[key_prop]
        try:
            txt_val = getattr(the_module, val_prop)
            if txt_val:
                grph.add((package_node, lib_common.MakeProp(key_prop), lib_util.NodeLiteral(txt_val)))
        except AttributeError:
            pass


def AddInfo(grph,node, entity_ids_arr):
    package_key = entity_ids_arr[0]
    logging.debug("AddInfo package_key=%s",package_key)

    _add_info_from_pip(grph, node, package_key)

    _add_info_from_import(grph, node, package_key)


def AddImportedModules(grph, node, fil_nam, max_depth, disp_packages, disp_files):
    """This adds to a node representing a Python package,
    a node for each package recursively imported by this one."""

    # TODO: At the moment, this is NOT RECURSIVE !!!
    logging.debug("AddImportedModules filNam=%s dispPackages=%d dispFiles=%d", fil_nam, disp_packages, disp_files)
    filename, file_extension = os.path.splitext(fil_nam)
    filextlo = file_extension.lower()
    if filextlo not in [".py", ".pyw"]:
        return

    finder = modulefinder.ModuleFinder()
    try:
        finder.run_script(fil_nam)
    except TypeError as exc:
        lib_common.ErrorMessageHtml("Error loading Python script %s:%s" % (fil_nam, str(exc)))

    AddImportedModules.dictModules = dict()

    # A cache which associates a node to a Python module name.
    def get_modu_node(modu_nam):
        try:
            modu_node = AddImportedModules.dictModules[modu_nam]
        except KeyError:
            modu_node = MakeUri(modu_nam)
            AddImportedModules.dictModules[modu_nam] = modu_node
        return modu_node

    AddImportedModules.dictFiles = dict()

    # A cache which associates a node to a file name.
    def get_file_node(modu_fil):
        try:
            file_node = AddImportedModules.dictModules[modu_fil]
        except KeyError:
            file_node = lib_uris.gUriGen.FileUri(modu_fil)
            AddImportedModules.dictModules[modu_fil] = file_node
        return file_node

    for modu_nam, mod in six.iteritems(finder.modules):
        split_nam = modu_nam.split(".")
        modu_fil = mod.__file__

        if len(split_nam) > max_depth:
            continue

        if disp_packages:
            modu_nod = get_modu_node(modu_nam)

            if disp_files and modu_fil:
                node_file = get_file_node(modu_fil)
                # node_file is the result of lib_common.NodeUrl
                grph.add((modu_nod, pc.property_rdf_data_nolist2, node_file))

            if len(split_nam) == 1:
                grph.add((node, prop_python_package, modu_nod))
                logging.debug("No parent: modu_nam=%s", (modu_nam))
            else:
                parent_modu_nam = ".".join(split_nam[:-1])
                parent_modu_nod = get_modu_node(parent_modu_nam)
                grph.add((parent_modu_nod, prop_python_requires, modu_nod))
                logging.debug("parent_modu_nam=%s modu_nam=%s", parent_modu_nam, modu_nam)

        if disp_files and not disp_packages:
            if modu_fil:
                node_file = get_file_node(modu_fil)
                if len(split_nam) == 1:
                    # TODO: Should be connected to the module.
                    grph.add((node, prop_python_package, node_file))
                else:
                    parent_modu_nam = ".".join(split_nam[:-1])
                    parent_modu_nod = get_modu_node(parent_modu_nam)
                    grph.add((parent_modu_nod, prop_python_requires, node_file))
