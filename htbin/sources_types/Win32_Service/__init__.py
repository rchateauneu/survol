"""
Windows service
"""

import os
import sys
import lib_util
import lib_common
from lib_common import pc

# Python for Windows extensions: pywin32
# https://sourceforge.net/projects/pywin32/
import win32service
import win32con
import win32api
import win32security

import lib_win32

def EntityOntology():
	return ( ["Name"],)

state_dictionary = ('Unknown', 'Stopped', 'Starting', 'Stopping', 'Running',
						'Continuing', 'Pausing', 'Paused')

# Enumerate Service Control Manager DB
typeFilter = win32service.SERVICE_WIN32
stateFilter = win32service.SERVICE_STATE_ALL

# Maybe similar to SC_MANAGER_ENUMERATE_SERVICE ?
accessSCM = win32con.GENERIC_READ

# It creates a dictionary containing all services keyed by their names.
def BuildSrvDict( hscm, machineName ):

	# One node for each service name.
	dictServiceToNode = {}

	try:
		# Old versions of this library do not have this function.
		statuses = win32service.EnumServicesStatusEx(hscm, typeFilter, stateFilter)
		# li={'ControlsAccepted': 0, 'ServiceType': 32, 'DisplayName': 'WWAN AutoConfig', 'ServiceSpecificExitCode': 0, 'ProcessId': 0, 'ServiceFlags': 0, 'CheckPoint': 0, 'ServiceName': 'WwanSvc', 'Win32ExitCode': 1077, 'WaitHint': 0, 'CurrentState': 1},
		for lst in statuses:
			# sys.stderr.write("lst="+str(lst)+"\n")

			serviceName = lst['ServiceName']
			lst["depends_in"] = []
			lst["depends_out"] = []

			dictServiceToNode[ serviceName ] = lst

	# except AttributeError:
	except Exception:
		statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)
		# li=('wuauserv', 'Windows Update', (32, 4, 453, 0, 0, 0, 0))
		for svc in statuses:
			sys.stderr.write("service=%s\n" % str(svc) )
			# TODO: This must match the keys of EnumServicesStatusEx
			# lst = { "ServiceName":serviceName, "DisplayName":descript, "CurrentState": status}
			lst = { "ServiceName":svc[0], "DisplayName":svc[1], "CurrentState": svc[2][1]}
			lst["depends_in"] = []
			lst["depends_out"] = []
			# A Win32 service status object is represented by a tuple
			# 0: serviceType
			# 1: serviceState
			# 2: controlsAccepted
			# 3: win32ExitCode
			# 4: serviceSpecificErrorCode
			# 5: checkPoint
			# 6: waitHint

			dictServiceToNode[ svc[0] ] = lst

			try:
				hsvc=win32service.OpenService(hscm, svc[0], win32service.SERVICE_CHANGE_CONFIG)

				# TODO: WHY DOING THIS ????? MAYBE FOR TESTING THE SERVICE PRESENCE ??

				#win32service.ChangeServiceConfig(hsvc, win32service.SERVICE_NO_CHANGE,
				#	win32service.SERVICE_DISABLED, win32service.SERVICE_NO_CHANGE, None, None,0,
				#	None,None,None,None)
				win32service.CloseServiceHandle(hsvc)
			except Exception:
				# Might receive "Access is denied" if this is on a remote machine.
				lst["ProcessId"] = 999999
				pass

	return dictServiceToNode

# This builds the network of services dependencies.
# This is really a hack but ok for prototyping. Why? Performances ?
# tmplog because a timeout prevents Apache log to display sys.stderr.
def BuildSrvNetwork( machineName ):
	sys.stderr.write("BuildSrvNetwork machineName=%s localhost=%s\n" % (machineName,lib_util.currentHostname))

	machName_or_None, imper = lib_win32.MakeImpersonate(machineName)

	# SC_MANAGER_ENUMERATE_SERVICE
	hscm = win32service.OpenSCManager(machName_or_None, None, accessSCM)

	dictServiceToNode = BuildSrvDict( hscm, machineName )

	# Now links the services together.
	for serviceName in dictServiceToNode:
		# nodeService = dictServiceToNode[ serviceName ]
		# sys.stderr.write("BuildSrvNetwork serviceName=%s\n" % (serviceName))

		try:
			hdnSrv = win32service.OpenService( hscm, serviceName, win32service.SERVICE_ENUMERATE_DEPENDENTS )
			depSrvLst = win32service.EnumDependentServices( hdnSrv, win32service.SERVICE_STATE_ALL )

			for depSrv in depSrvLst:
				# sys.stderr.write("depSrv=%s\n" % ( depSrv[0] ) )
				subServiceName = depSrv[0]
				try:
					nodeSubService = dictServiceToNode[ subServiceName ]
				except KeyError:
					sys.stderr.write("Main=%s Sub=%s NOT CREATED\n" % ( serviceName, subServiceName ) )
					continue

				dictServiceToNode[ subServiceName ]["depends_in"].append( serviceName )
				dictServiceToNode[ serviceName ]["depends_out"].append( subServiceName )

			# NOT SURE ABOUT THIS, NEVER TESTED BUT SEEMS NECESSARY.
			win32service.CloseServiceHandle(hdnSrv)
		except:
			exc = sys.exc_info()
			# With wsgi and maybe cgi, many dependencies not seen. OK with Apache.
			# Why especially these ones which have a lot of dependencies ?
			# BuildSrvNetwork serviceName=RpcSs:
			# BuildSrvNetwork serviceName=RpcEptMapper
			# BuildSrvNetwork serviceName=DcomLaunch:
			# BuildSrvNetwork serviceName=pla:
			sys.stderr.write("BuildSrvNetwork serviceName=%s: Caught: %s\n" % ( serviceName, str(exc) ) )
			# pywintypes.error: (5, 'OpenService', 'Access is denied.')

			pass

	return dictServiceToNode

# Writes the key-values dicts of a service into a RDF node.
def DictServiceToNode( grph, serviceDict, machineName = None ):
	# sys.stderr.write("DictServiceToNode machineName=%s enter.\n" % str(machineName))

	# TODO: This is a process but not only. How to display that?
	serviceName = serviceDict['ServiceName']

	# NOTE: SOON, ALL ENTITIES WILL HAVE THEIR HOSTNAME.
	if machineName in [ None, ""]:
		nodeService = lib_common.gUriGen.ServiceUri( serviceName )
	else:
		nodeService = lib_common.RemoteBox(machineName).ServiceUri( serviceName )

	try:
		currentStateIdx = serviceDict['CurrentState']
		currentStateNam = state_dictionary[ currentStateIdx ]
	except KeyError:
		currentStateNam = "Unknown state key"
	except IndexError:
		currentStateNam = "Unknown state index"

	grph.add( (nodeService, pc.property_information, lib_common.NodeLiteral(serviceDict['DisplayName']) ) )
	# TODO: Change color with the state. ASSOCIATE COLOR TO PAIRS (Property + Literal value) ? SPECIALLY CODED VALUE WITH HTML TAGS ?

	servicePid = serviceDict['ProcessId']

	# Display is as compact as possible to help routing. Informaitonal only.
	if servicePid != 0:
		# TODO: Plutot mettre un lien vers le process mais afficher comme un literal.
		state_string = str(servicePid) + "/" + currentStateNam
		# grph.add( (nodeService, pc.property_pid, lib_common.NodeLiteral(servicePid) ) )
		grph.add( (nodeService, pc.property_pid, lib_common.NodeLiteral(state_string) ) )
	else:
		# grph.add( (nodeService, pc.property_service_state, lib_common.NodeLiteral(currentStateNam) ) )
		grph.add( (nodeService, pc.property_service_state, lib_common.NodeLiteral(currentStateNam) ) )
	return nodeService


def FullServiceNetwork(grph,machineName):
	sys.stderr.write("FullServiceNetwork machineName=%s enter.\n" % str(machineName))
	dictServiceToNode = {}
	dictServiceMap = BuildSrvNetwork( machineName )

	# Creates all the RDF nodes.
	for serviceName in dictServiceMap:
		serviceDict = dictServiceMap[ serviceName ]
		dictServiceToNode[ serviceName ] = DictServiceToNode( grph, serviceDict, machineName )

	# Now links the services together.
	for serviceName in dictServiceMap:
		serviceDict = dictServiceMap[ serviceName ]
		nodeService = dictServiceToNode[ serviceName ]
		for subServiceName in serviceDict["depends_in"]:
			nodeSubService = dictServiceToNode[ subServiceName ]
			grph.add( (nodeService, pc.property_service, nodeSubService ) )
	sys.stderr.write("FullServiceNetwork machineName=%s leaving.\n" % str(machineName))


# Ajoute des informations variees autour du node d'un service.
# N'a pas besoin d'etre extremement rapide.
def AddInfo(grph,node,entity_ids_arr):
	serviceNam = entity_ids_arr[0]
	sys.stderr.write("AddInfo serviceNam=%s\n" % serviceNam )

	machName_or_None, imper = lib_win32.MakeImpersonate("")
	hscm = win32service.OpenSCManager(machName_or_None, None, accessSCM)

	try:
		status = win32service.SERVICE_QUERY_CONFIG|win32service.SERVICE_QUERY_STATUS|win32service.SERVICE_INTERROGATE|win32service.SERVICE_ENUMERATE_DEPENDENTS
		hdnSrv = win32service.OpenService( hscm, serviceNam, status )
		lstSrvPairs = win32service.QueryServiceStatusEx(hdnSrv)
		win32service.CloseServiceHandle(hdnSrv)
	except Exception:
		exc = sys.exc_info()[1]
		# Probably "Access is denied"
		sys.stderr.write("AddInfo Caught:%s\n" % str(exc) )
		lstSrvPairs = dict()
		try:
			lstSrvPairs[ "Status" ] = str(exc[2])
		except:
			lstSrvPairs[ "Status" ] = str(exc)

	# CheckPoint                0
	# ControlsAccepted          1
	# CurrentState              4
	# ProcessId              3176
	# ServiceFlags              0
	# ServiceSpecificExitCode	0
	# ServiceType              16
	# WaitHint                  0
	# Win32ExitCode             0
	for keySrv in lstSrvPairs:
		sys.stderr.write("AddInfo keySrv:%s\n" % keySrv )
		valSrv = lstSrvPairs[ keySrv ]
		if keySrv == "ProcessId":
			if int(valSrv) != 0:
				nodeProc = lib_common.gUriGen.PidUri(valSrv)
				grph.add( (nodeProc, pc.property_pid, lib_common.NodeLiteral(valSrv) ) )
				grph.add( (node,lib_common.MakeProp(keySrv), nodeProc ) )
		elif keySrv == "ServiceType":
			svcTypSrc = ""
			svcTypInt = int(valSrv)
			if svcTypInt & win32service.SERVICE_KERNEL_DRIVER: svcTypSrc += "KERNEL_DRIVER "
			if svcTypInt & win32service.SERVICE_FILE_SYSTEM_DRIVER: svcTypSrc += "FILE_SYSTEM_DRIVER "
			#if svcTypInt & win32service.SERVICE_ADAPTER: svcTypSrc += "ADAPTER "
			#if svcTypInt & win32service.SERVICE_RECOGNIZER_DRIVER: svcTypSrc += "RECOGNIZER_DRIVER "
			if svcTypInt & win32service.SERVICE_WIN32_OWN_PROCESS: svcTypSrc += "WIN32_OWN_PROCESS "
			if svcTypInt & win32service.SERVICE_WIN32_SHARE_PROCESS: svcTypSrc += "WIN32_SHARE_PROCESS "
			if svcTypInt & win32service.SERVICE_WIN32: svcTypSrc += "WIN32 "
			if svcTypInt & win32service.SERVICE_INTERACTIVE_PROCESS: svcTypSrc += "INTERACTIVE_PROCESS "

			grph.add( (node,lib_common.MakeProp(keySrv), lib_common.NodeLiteral(svcTypSrc) ) )

		elif keySrv == "CurrentState":
			statesArray = (
				"SERVICE_STOPPED",
				"SERVICE_START_PENDING",
				"SERVICE_STOP_PENDING",
				"SERVICE_RUNNING",
				"SERVICE_CONTINUE_PENDING",
				"SERVICE_PAUSE_PENDING",
				"SERVICE_PAUSED" )

			# Fetches from the module a constant with this value.
			srcStatSrc = valSrv
			for srvStatVar in statesArray:
				if valSrv == getattr(win32service, srvStatVar):
					srcStatSrc = srvStatVar
					break
			grph.add( (node,lib_common.MakeProp(keySrv), lib_common.NodeLiteral(srcStatSrc) ) )

		else:
			grph.add( (node,lib_common.MakeProp(keySrv), lib_common.NodeLiteral(valSrv) ) )

	return
