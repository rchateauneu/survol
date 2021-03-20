#!/usr/bin/env python

"""
Installed Python packages
"""

import sys
import socket
import logging
import lib_util
import lib_common
import lib_python
from lib_properties import pc

import pip

from sources_types import python
from sources_types.python import package

# werkzeug 0.10.4 (c:\python27\lib\site-packages\werkzeug-0.10.4-py2.7.egg)
#
# >>> dir(installed_packages[0])
# ['PKG_INFO', '__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
#  '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
#  '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_dep_map', '_get_metadata', '_key', '_provider', '_relo
# ad_version', '_version', '_warn_legacy_version', 'activate', 'as_requirement', 'check_version_conflict', 'clone', 'egg_name', 'extra
# s', 'from_filename', 'from_location', 'get_entry_info', 'get_entry_map', 'has_version', 'hashcmp', 'insert_on', 'key', 'load_entry_p
# oint', 'location', 'parsed_version', 'platform', 'precedence', 'project_name', 'py_version', 'requires', 'version']


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    Main.dictKeyToPckg = dict()

    def key_to_pckg_node(key):
        try:
            package_node = Main.dictKeyToPckg[key]
        except KeyError:
            package_node = package.MakeUri(key)
            Main.dictKeyToPckg[ key ] = package_node
        return package_node

    grph = cgiEnv.GetGraph()

    # TODO: What about several Python versions ?
    installed_packages = lib_python.PipGetInstalledDistributions()

    cnt = 0

    # TODO: Maybe the version should be part of the key.
    for pckg in installed_packages:
        cnt += 1

        logging.debug("cnt=%d key=%s", cnt,pckg.key)

        # With this module, "dot" crashes...
        # TODO: WHY IS THIS BROKEN ?????
        if pckg.key in ["aff4-snappy"]:
            continue

        package_node = key_to_pckg_node(pckg.key)
        grph.add((package_node, package.propPythonVersion, lib_util.NodeLiteral(pckg.version)))

        req_pckg = pckg.requires()
        if req_pckg:
            for sub_req in pckg.requires():
                sub_node = key_to_pckg_node(sub_req.key)

                # TODO: Should do that on the edge !!!!!
                # [('>=', '4.0.0')]+[]+[('>=','4.0')]+[]
                # aSpecs = sub_req.specs
                # if aSpecs:
                #    grph.add( (sub_node, lib_common.MakeProp("Condition"), lib_util.NodeLiteral( str(aSpecs) ) ) )

                grph.add((package_node, package.propPythonRequires, sub_node))
        else:
            grph.add((lib_common.nodeMachine, package.propPythonPackage, package_node))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
