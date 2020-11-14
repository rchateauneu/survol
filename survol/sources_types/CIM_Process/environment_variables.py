#!/usr/bin/env python

"""
Environment variables
"""

import os
import re
import sys
import psutil
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process


# https://stackoverflow.com/questions/11887762/compare-version-strings-in-python
def versiontuple(v):
    filled = []
    for apoint in v.split("."):
        filled.append(apoint.zfill(8))
    return tuple(filled)


# psutil.__version__ '3.2.2'
# The feature environ is new in version 4.0.0.
def Usable(entity_type, entity_ids_arr):
    """Psutil version must be at least 4.0.0"""
    usab = versiontuple(psutil.__version__) >= versiontuple("4.0.0")
    DEBUG("psutil.__version__=%s usab=%d", psutil.__version__, usab)
    return usab


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    try:
        procid = int(cgiEnv.GetId())
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")

    obj_proc = CIM_Process.PsutilGetProcObj(procid)

    env_prop = lib_common.MakeProp("environment")

    try:
        # Psutil version after 4.0.0
        envs_dict = obj_proc.environ()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:" + str(exc))

    node_process = lib_common.gUriGen.PidUri(procid)

    for env_key in envs_dict :
        env_val = envs_dict[env_key]
        DEBUG("env_key=%s env_val=%s", env_key, env_val)
        node_env_nam = lib_util.NodeLiteral(env_key)

        # When a file or a directory displayed with a node,
        # its name is shortened so it can fit into the table.,
        # so it is less visible.

        # Some are probably for Windows only.
        if env_key in ["PATH", "PSMODULEPATH", "PYPATH"]:
            val_split = env_val.split(os.pathsep)
            nod_fil_arr = [lib_common.gUriGen.DirectoryUri(filNam) for filNam in val_split]
            nod_fil_arr_nod = lib_util.NodeLiteral(nod_fil_arr)
            grph.add((node_env_nam, pc.property_rdf_data_nolist2, nod_fil_arr_nod))
        elif os.path.isdir(env_val):
            nod_fil = lib_common.gUriGen.DirectoryUri(env_val)
            grph.add((node_env_nam, pc.property_rdf_data_nolist2, nod_fil))
        elif os.path.exists(env_val):
            nod_fil = lib_common.gUriGen.FileUri(env_val)
            grph.add((node_env_nam, pc.property_rdf_data_nolist2, nod_fil))
        else:
            # TODO: Beware that "\L" is transformed into "<TABLE>" by Graphviz !!!
            env_val_clean = env_val.replace(">", "_").replace("<", "_").replace("&", "_").replace("\\", "_")
            node_env_value = lib_util.NodeLiteral(env_val_clean)
            grph.add((node_env_nam, pc.property_rdf_data_nolist2, node_env_value))
        grph.add((node_process, env_prop, node_env_nam))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [env_prop])


if __name__ == '__main__':
    Main()

