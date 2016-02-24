#!/usr/bin/python

import os
import sys
import time
import psutil
import lib_util
import lib_common
from lib_properties import pc
import rdflib

cgiEnv = lib_common.CgiEnv("Disk usage")
partitionNam = cgiEnv.GetId()

# partitionNode = lib_util.EntityUri('partition', partitionNam )
partitionNode = lib_common.gUriGen.DiskPartitionUri( partitionNam )

grph = rdflib.Graph()

dskUsage = psutil.disk_usage(partitionNam)

grph.add( ( partitionNode, pc.property_disk_used, rdflib.Literal(dskUsage.used) ) )
grph.add( ( partitionNode, pc.property_disk_free, rdflib.Literal(dskUsage.free) ) )

cgiEnv.OutCgiRdf(grph)


