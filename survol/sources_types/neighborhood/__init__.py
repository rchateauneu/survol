"""
Browse neighborhood services and agents
"""

import re
import sys
import logging
import lib_common

# There is no WMI neighborhood because all Windows machine have WMI.

# Typical configuration in slp.reg file.
#
# service:wbem:http://mymachine,en,65535
# description=OpenPegasus sous Windows 7
#
# # Definitions must be separated by an empty line.
# service:survol:http://mymachine:8000/survol/entity.py,en,65535
# description=Survol Windows 7
#
# $ slptool findsrvtypes
# service:wbem:http
# service:survol:http
#
# $ slptool findsrvs service:survol
# service:survol:http://mymachine:8000/survol/entity.py,65535
#
# $ slptool findattrs service:wbem:http://mymachine
# (description=OpenPegasus sous Windows 7)
# (description=OpenPegasus sous Windows 7)
# (description=OpenPegasus sous Windows 7)
#

# It could probably use the Python3 module pyslp.


# This returns a map containing the key-value pairs of the attributes
# of this service.
def GetSLPAttributes(service_name, slp_host):
    dict_attributes = {}

    cmd_slp_find_attrs = ["slptool", 'findattrs', 'service:%s:%s' % (service_name, slp_host), ]

    resu_find_attrs = lib_common.SubProcPOpen(cmd_slp_find_attrs)

    out_stream_find_attrs, err_stream_find_attrs = resu_find_attrs.communicate()

    split_resu_find_attrs = out_stream_find_attrs.split("\n")

    for lin_resu_find_attrs in split_resu_find_attrs:
        logging.debug("GetSLPAttributes slpHost=%s lin_resu_find_attrs=%s", slp_host, lin_resu_find_attrs)
        # service:survol:http://mymachine:8000/survol/entity.py,65535
        # service:wbem:http://mymachine,65535
        mtch_find_attrs = re.match(r'\(([^=]*)=([^)]*)\)', lin_resu_find_attrs)
        if mtch_find_attrs:
            slp_attr_key = mtch_find_attrs.group(1)
            slp_attr_val = mtch_find_attrs.group(2)
            dict_attributes[slp_attr_key] = slp_attr_val
        else:
            logging.debug("No match for attributes:%s", lin_resu_find_attrs)

    return dict_attributes


def GetSLPServices(service_name):
    dict_services = {}

    cmd_slp_tool = ["slptool", 'findsrvs', 'service:' + service_name,]

    resu_p_open = lib_common.SubProcPOpen(cmd_slp_tool)

    out_stream_slp_tool, err_stream_slp_tool = resu_p_open.communicate()

    split_resu_slp_tool = out_stream_slp_tool.split("\n")

    for lin_resu_slp_tool in split_resu_slp_tool:
        logging.debug("GetSLPServices serviceName=%s lin_resu_slp_tool=%s", service_name, lin_resu_slp_tool)
        # service:survol:http://mymachine:8000/survol/entity.py,65535
        # service:wbem:http://mymachine,65535
        mtch_spl_tool = re.match(r'service:[^:]*:([^,]*)(.*)', lin_resu_slp_tool)
        if mtch_spl_tool:
            slp_host = mtch_spl_tool.group(1)
            slp_attrs = GetSLPAttributes(service_name, slp_host)
            dict_services[slp_host] = slp_attrs
        else:
            logging.debug("No match:%s", lin_resu_slp_tool)

    return dict_services
