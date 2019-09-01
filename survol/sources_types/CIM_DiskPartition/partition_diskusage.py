#!/usr/bin/env python

"""
Disk usage
"""

import os
import sys
import time
import psutil
import lib_util
import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	partitionNam = cgiEnv.GetId()

	# partitionNode = lib_util.EntityUri('partition', partitionNam )
	partitionNode = lib_common.gUriGen.DiskPartitionUri( partitionNam )

	grph = cgiEnv.GetGraph()

	dskUsage = psutil.disk_usage(partitionNam)

	grph.add( ( partitionNode, pc.property_disk_used, lib_common.NodeLiteral(dskUsage.used) ) )
	grph.add( ( partitionNode, pc.property_disk_free, lib_common.NodeLiteral(dskUsage.free) ) )

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
