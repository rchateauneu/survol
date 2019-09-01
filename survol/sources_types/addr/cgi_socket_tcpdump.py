#!/usr/bin/env python

"""
Socket content sniffing
"""

import os
import sys
import time
import lib_common
from lib_properties import pc

# def Daemon(blocking):
# 	import multiprocessing
#
# 	if blocking:
# 		# This can happen only
#
#
# 		# If queue not there creates it.
# 		try:
# 			persistent_queue
# 		except NameError:
# 			# THIS MUST BE GLOBAL !!!
# 			persistent_queue = multiprocessing.Queue()
#
# 		# If process not here starts it: The process reads incoming data
# 		try:
# 			tcpdump_process
# 		except NameError:
# 			# Il faut reellement creer un process pour ne pas rester en attente
# 			# d'une entree-sortie. asyncio pas disponible en Python 2.
#
# 			class MyExec(threading.Thread):
# 				def __init__(self):
# 					pass
#
# 				def run(self):
# 					output = SubProcess.start("tcpdump")
# 					for lin in output:
# 						persistent_queue.put_nowait(lin)
# 					pass
#
# 			# THIS MUST BE GLOBAL !!!
# 			tcpdump_process = MyExec()
# 			tcpdump_process.start()
#
#
# 		while True:
# 			try:
# 				yield persistent_queue.get_nowait()
# 			except multiprocessing.Queue.Empty:
# 				return
# 	else:
# 		# Starts the process, and transforms the output into triplets.
# 		# This should not never block.
# 		return []


def Main():
	cgiEnv = lib_common.CgiEnv()
	socketNam = cgiEnv.GetId()

	# Pass Daemon function to CgiEnv which will call Daemon in blocking or non-blocking mode.
	# CgiEnd detects in a Damon() function exists in the module of the caller.
	# The caller knows that more data will come.
	# The advantage of the non blocking mode is that no data is lost,
	# and the creation of the returned objects is done in parallel.


	grph = cgiEnv.GetGraph()

	lib_common.ErrorMessageHtml("Not implemented yet")

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
