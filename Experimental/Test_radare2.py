#!/usr/bin/env python

import r2pipe
import sys
import os
import json
import re
import networkx as nx
from time import time
from datetime import datetime
from base64 import b64decode



from hashlib import sha1, md5
from os.path import basename, getsize
import pefile
import time
import math


# receives a string, containing a symbol a la radare2
# returns the sole API name

def gimmeDatApiName(wholeString):
	# TODO do something smarter here one day..
	if '.dll_' in wholeString:
		apiName = wholeString.split('.dll_')[1].replace(']','')
		return apiName
	elif '.DLL_' in wholeString:
		apiName = wholeString.split('.DLL_')[1].replace(']','')
		return apiName
	elif '.SYS_' in wholeString:
		apiName = wholeString.split('.SYS_')[1].replace(']','')
		return apiName
	elif '.exe_' in wholeString:
		apiName = wholeString.split('.exe_')[1].replace(']','')
		return apiName
	elif 'sym._' in wholeString:
		apiName = wholeString.split('sym._')[1].replace(']','')
		return apiName
	else:
		print "DAT API STRING was malformed or something, pls check %s" % wholeString
		return wholeString

# checks whether a string is pure ascii

def is_ascii(myString):
	try:
		myString.decode('ascii')
		return True
	except UnicodeDecodeError:
		return False

# SAMPLE ATTRIBUTE GETTERS

 # MD5
 # filename
 # filetype
 # ssdeep
 # imphash
 # size
 # compilationTS
 # address of EP
 # EP section
 # number of section
 # original filename
 # number TLS sections

def sha1hash(path):
	content = file(path, 'rb').read()
	return sha1(content).hexdigest()

def md5hash(path):
	content = file(path, 'rb').read()
	return md5(content).hexdigest()

def getFilename(path):
	return basename(path)

def getFiletype(path):
	try:
		import magic
	except ImportError as exc:
		return "magic:"+str(exc)
	return magic.from_file(path)

def getFilesize(path):
	return getsize(path)

def getPeSubsystem(path):
	pass

def getSsdeep(path):
	try:
		import pydeep
	except ImportError as exc:
		return "pydeep:"+str(exc)
	return pydeep.hash_file(path)

def getImphash(pe):
	return pe.get_imphash()

def getCompilationTS(pe):
	return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp))

def getEPAddress(pe):
	return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def getSectionCount(pe):
	return pe.FILE_HEADER.NumberOfSections

def getOriginalFilename(pe):
	oriFilename = ""
	if hasattr(pe, 'VS_VERSIONINFO'):
		if hasattr(pe, 'FileInfo'):
			for entry in pe.FileInfo:
				if hasattr(entry, 'StringTable'):
					for st_entry in entry.StringTable:
						for str_entry in st_entry.entries.items():
							if 'OriginalFilename' in str_entry:
								# UGLY DIRTY TRICK to sanitize values
								try:
									oriFilename = str(str_entry[1].decode("ascii", "ignore"))
								except:
									oriFilename = "PARSINGERR"
	return oriFilename

def getEPSection(pe):
	name = ''
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	pos = 0
	for sec in pe.sections:
		if (ep >= sec.VirtualAddress) and \
		   (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
			name = sec.Name.replace('\x00', '')
			name = name.decode("ascii", "ignore")
			break
		else:
			pos += 1
	return (name + "|" + pos.__str__())

def getTLSSectionCount(pe):
	idx = 0
	if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and
	   pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
		callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

		while True:
			func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
			if func == 0:
				break
			idx += 1
	return idx

# Returns Entropy value for given data chunk
def Hvalue(data):
	if not data:
		return 0

	entropy = 0#
	for x in range(256):
		p_x = float(data.count(chr(x))) / len(data)
		if p_x > 0:
			entropy += - p_x * math.log(p_x, 2)

	return entropy


def getCodeSectionSize(pe):

	for section in pe.sections:
		print section

def getSectionInfo(pe):

	# Section info: names, sizes, entropy vals
	sects = []
	vadd = []
	ent = []
	secnumber = getSectionCount(pe)

	for i in range(12):

		if (i + 1 > secnumber):
			strip = ""
			strap = ""
			entropy = ""

		else:
			stuff = pe.sections[i]
			strip = stuff.Name.replace('\x00', '')
			strap = str(stuff.SizeOfRawData).replace('\x00', '')

			entropy = Hvalue(stuff.get_data())

		section_name = ""
		try:
			section_name = strip.decode("ascii", "ignore")
		except:
			section_name = "PARSINGERR"

		sects.append(section_name)
		ent.append(entropy)
		if strap.isdigit():
			vadd.append(int(strap))
		else:
			vadd.append('')

	secinfo = sects + vadd + ent
	return secinfo



def getAllAttributes(path):

	allAtts = {}

	allAtts['md5'] = md5hash(path)
	allAtts['sha1'] = sha1hash(path)
	allAtts['filename'] = getFilename(path)
	allAtts['filetype'] = getFiletype(path)
	allAtts['ssdeep'] = getSsdeep(path)
	allAtts['filesize'] = getFilesize(path)

	try:
		pe = pefile.PE(path)
		if (pe.DOS_HEADER.e_magic == int(0x5a4d) and pe.NT_HEADERS.Signature == int(0x4550)):
			allAtts['imphash'] = getImphash(pe)
			allAtts['compilationts'] = getCompilationTS(pe)
			allAtts['addressep'] = getEPAddress(pe)
			allAtts['sectionep'] = getEPSection(pe)
			allAtts['sectioncount'] = getSectionCount(pe)
			allAtts['sectioninfo'] = getSectionInfo(pe)
			allAtts['tlssections'] = getTLSSectionCount(pe)
			allAtts['originalfilename'] = getOriginalFilename(pe)

	except (pefile.PEFormatError):
		pass

	return allAtts



# Checks whether an address is located in an executable section
def isValidCode(callAddress, sectionsList):

	# sectionsList contains executable sections as 2-element lists, containing start and end of each section
	for execSection in sectionsList:
		if int(callAddress, 16) >= execSection[0] and int(callAddress, 16) < execSection[1]:
			return True
	return False


# Returns a list of executable sections
def getCodeSections():

	returnSections = []

	# regular expression to pick out the executable section(s)
	execSection = re.compile("perm=....x")

	# will return the section table from radare2
	sections = R2PY.cmd("iS")

	sectionData = {}

	for line in sections.splitlines():
		if re.search(execSection, line):

			for element in line.split():
				items = element.split('=')
				sectionData[items[0]] = items[1]

			start = int(sectionData['vaddr'], 16)
			end = start + int(sectionData['vsz'])
			psize = int(sectionData['sz'])
			returnSections.append([start, end, psize])

	return returnSections


# Returns an executables imports as a list
def getIat():

	iatlist = []
	cmd = "iij"
	iatjson = json.loads(R2PY.cmd(cmd))
	for item in iatjson:
		iatlist.append(hex(item['plt']))
	return iatlist


# Returns a dictionary of xrefs to symbols
def crossRefScan():

	cmd = "axtj @@ sym.*"
	finalCalls = {}

	# fixing the JSON...
	temp = R2PY.cmd(cmd).replace('\n', ',')
	temp = "[" + temp + "]"

	xrefj = json.loads(temp)
	for xrefitem in xrefj:
		for xreflevel2 in xrefitem:

			# not data xref means its code or call
			if xreflevel2['type'] != 'd':
				finalCalls[hex(xreflevel2['from'])] = xreflevel2['opcode']
				pass

			# data potentially means API referenced by register; please note these are rather uncommon in the long list of symbol refs
			# thus, bottelneck in parsing speed lies in number of refs
			if xreflevel2['type'] == 'd' and ( xreflevel2['opcode'].startswith('mov') or xreflevel2['opcode'].startswith('lea') ):

				# 'grepping' out the register from mov/lea operation
				register = xreflevel2['opcode'].split()[1].replace(',','')

				# disassemble downwards; mmmaybe smarter to disassemble until end of function, but possible that there is no function at all
				# TODO find end of function, just in case
				cmd = "pd 300 @ " + hex(xreflevel2['from'])
				moreDisasm = R2PY.cmd(cmd)

				# possible branches towards target
				realCall = "call %s" % register
				aJmp = "jmp %s" % register

				for disasmLine in moreDisasm.splitlines()[1:]:
					if realCall in disasmLine or aJmp in disasmLine:
						#found a call!!
						temp = disasmLine + ";" + xreflevel2['opcode'].split(',')[1].rstrip()
						tempSplit = temp.split()
						finalCalls[hex(int(tempSplit[0], 16))] = ' '.join(tempSplit[1:])

					elif register in disasmLine:
						# TODO if mov dword abc, reg is found -> follow abc?
						# TODO could be parsed in more detail, e.g. mov dword, reg won't change the reg
						#print disasmLine

						break
						#pass
	return finalCalls


# Parses the binary for strings and their references to nodes
def stringScan(debugDict):

	# Workflow is: get string, get xrefs to string if any, get functions of xrefs if any; fit node in graph with the string
	allMyStrings = []

	# izzj parses entire binary
	stringCmd = "izzj"
	strings = R2PY.cmd(stringCmd)
	parsedStrings = json.loads(strings)

	debugDict['stringsDangling'] = []
	debugDict['stringsNoRef'] = []

	i = 0
	j = 1
	while i < len(parsedStrings):
		stringItem = parsedStrings[i]

		# Strings when retrieved through izzj command are BASE64 encoded
		thatOneString = b64decode(stringItem['string']).replace('\\',' \\\\ ')
		thatOneString.replace('\'', '')

		if is_ascii(thatOneString):

			xrefCmd = "axtj @ " + hex(stringItem['vaddr'])
			stringXrefsJ = R2PY.cmd(xrefCmd)

			if stringXrefsJ:
				stringXrefs = json.loads(stringXrefsJ)

				# check whether string item is root of list of strings
				j = 1
				lastItem = stringItem
				while (i+j) < len(parsedStrings):
					nextStringItem = parsedStrings[i+j]
					lastAddr = lastItem['vaddr']
					lastSize = lastItem['size']

					# string offsets are 4 byte aligned, TODO check whether this is always the case
					padding = 4 - (lastSize % 4)
					if padding == 4:
						padding = 0
					nextAddr = lastAddr + lastSize + padding


					if nextAddr != nextStringItem['vaddr'] or hasXref(hex(nextStringItem['vaddr'])):
						# end.. exit here
						break
					else:
						thatOneString = thatOneString + "|" + b64decode(nextStringItem['string'])
						j = j + 1
						lastItem = nextStringItem

				# iterate refs on string, if any
				for ref in stringXrefs:
					stringAddr = hex(ref['from'])
					stringFuncRefCmd = "?v $FB @ " + stringAddr
					stringFuncRef = R2PY.cmd(stringFuncRefCmd)
					if stringFuncRef != '0x0':
						allMyStrings.append([stringAddr, stringFuncRef, thatOneString])
					else:
						# TODO this is merely still useful strings, see how to fit them in the graphs and db
						print( "DANGLING STRING NO FUNCREF %s %s" % (stringAddr, thatOneString))
						debugDict['stringsDangling'].append(thatOneString)

			else:
				debugDict['stringsNoRef'].append(thatOneString)

		if j > 1:
			i = i + j
		else:
			i = i + 1

	debugDict['stringsDanglingTotal'] = len(debugDict['stringsDangling'])
	debugDict['stringsNoRefTotal'] = len(debugDict['stringsNoRef'])
	return allMyStrings


# Text whether xrefs exist for given address
def hasXref(vaddr):

	refs = R2PY.cmd("axtj @ " + vaddr)
	if refs:
		return True
	else:
		return False


# Creating the NetworkX graph, nodes are functions, edges are calls or callbacks
def createSeGraph():

	graphity = nx.DiGraph()
	debugDict = {}

	functions = R2PY.cmd("aflj")
	if functions:
		functionList=json.loads(functions)
	else:
		functionList = []

	sectionsList = getCodeSections()

	xlen = 0
	for execSec in sectionsList:
		xlen = xlen + execSec[2]
	debugDict['xsectionsize'] = xlen

	# CREATING THE GRAPH

	refsGlobalVar = 0
	refsUnrecognized = 0
	refsFunc = 0
	debugDict['functions'] = len(functionList)

	for item in functionList:

		graphity.add_node(hex(item['offset']), size=item['size'], calltype=item['calltype'], calls=[], apicallcount=0, strings=[])

	for item in functionList:

		for xref in item['callrefs']:

			if xref['type'] == 'C':

				# If an edge is added, that includes a non-existent node, the node will be added, but w/o the necessary attributes
				# Thasss why we iterate twice, can theoretically be speeded up but needs testing
				if hex(xref['addr']) in graphity:
					graphity.add_edge(hex(item['offset']), hex(xref['addr']), pos=hex(xref['at']))
					refsFunc = refsFunc + 1

				elif hex(xref['addr']) in getIat():
					pass

				elif not isValidCode(hex(xref['addr']), sectionsList):
					print( "DANGLING call to address outside code section, glob var, dynamic API loading %s -> %s" % (hex(item['offset']), hex(xref['addr'])) )
					refsGlobalVar = refsGlobalVar + 1

				else:
					print( "FAIL: Call to code thats not a function, an import/symbol or otherwise recognized. Missed function perhaps. %s -> %s" % (hex(item['offset']), hex(xref['addr'])) )
					refsUnrecognized = refsUnrecognized + 1

	print( '* %s Graph created with NetworkX ' % str(datetime.now()) )
	debugDict['refsFunctions'] = refsFunc
	debugDict['refsGlobalVar'] = refsGlobalVar
	debugDict['refsUnrecognized'] = refsUnrecognized

	apiRefs = crossRefScan()

	callNum = len(apiRefs)
	missesNum = 0

	# FITTING GRAPH WITH API REFS

	for call in apiRefs:

		# get the address of the function, that contains the call to a given symbol
		refAddressCmd = "?v $FB @ " + call
		funcAddress = R2PY.cmd(refAddressCmd)

		if funcAddress in graphity:

			# node(funcAddress) has attribute calls, which contains a list of API calls
			api = gimmeDatApiName(apiRefs[call])

			graphity.node[funcAddress]['calls'].append([call, api])
			apicount = graphity.node[funcAddress]['apicallcount']
			graphity.node[funcAddress]['apicallcount'] = apicount + 1

		# detected API call reference does not resolve to a function offset, insert handling for this here
		else:
			print( "DANGLING API CALL %s %s" % (call, apiRefs[call]))
			missesNum = missesNum+1

	# debug: print total API refs and functionless API refs, maybe indicator for obfuscated code
	print( '* %s Graph extended with API calls, %d calls in total, %d dangling w/o function reference ' % (str(datetime.now()), callNum, missesNum) )
	debugDict['apiTotal'] = callNum
	debugDict['apiMisses'] = missesNum


	# FITTING GRAPH WITH STRING REFS

	allTheStrings = stringScan(debugDict)
	stringrefs = 0

	for aString in allTheStrings:

		stringAddr = aString[0]
		stringFunc = aString[1]
		stringData = aString[2]

		# add string to respective function node in graph
		if stringFunc in graphity:
			graphity.node[stringFunc]['strings'].append([stringAddr, stringData])
			stringrefs = stringrefs + 1

		else:
			print( "\nFAIL: String's function not in graph %s %s" % (stringFunc, stringData))

	print( '* %s Graph extended with string references ' % (str(datetime.now())))
	debugDict['stringsReferencedTotal'] = stringrefs

	return graphity, debugDict


# Tag exports of DLLs
def analyzeExports(graphity):

	exportsj = json.loads(R2PY.cmd("iEj"))
	for item in exportsj:

		export_address = hex(item['vaddr'])
		export_name = item['name']

		if export_address in graphity:
			graphity.node[export_address]['type'] = 'Export'
			graphity.node[export_address]['alias'] = export_name


# Removing thunks as they make my graphs fat, replace by API calls
def thunkPruning(graphity):

	for aNode in graphity.nodes(data=True):

		# most obvious thunks, other thunks exist too, len seen was 11, 13
		# funclets that contain nothing but a jump to an import, and do not call other functions
		if aNode[1]['apicallcount'] == 1 and aNode[1]['size'] == 6 and not graphity.successors(aNode[0]):

			thunk = aNode[0]
			thunkApi = aNode[1]['calls'][0]

			# need to go on with radare from here, cause graphity doesn't know all the addressed of the xrefs to thunks from within a function
			# getting all xrefs on thunk, then getting function its located in to get to node of graph
			temp = R2PY.cmd("axtj " + thunk)

			thunkRefs = []
			if temp:
				thunkRefs = json.loads(temp)

			for aRef in thunkRefs:

				thunkCallAddr = hex(aRef['from'])
				thunkFuncRef = R2PY.cmd("?v $FB @ " + hex(aRef['from']))

				# if thunk's xrefs include a detected function then add thunk as a regular API call to calls list of respective node
				if thunkFuncRef != '0x0':
					graphity.node[thunkFuncRef]['calls'].append([thunkCallAddr, thunkApi[1]])

			# after xref to thunk has been added to all calling functions, remove thunk node from graph
			graphity.remove_node(thunk)


# DEPRECATED
def fixCallbacks(apiname):

	cmd = "axtj @@ sym.* | grep \"%s\"" % apiname
	temp = R2PY.cmd(cmd).replace(']\n[', ',')

	if temp:
		callbackApis = json.loads(temp)
		for item in callbackApis:
			function = R2PY.cmd("?v $FB @ " + hex(item['from']))
			R2PY.cmd("afr @ " + function)


# Adding edges to indirectly referenced functions, thread handlers and hook functions for now only
def tagCallbacks(graphity):

	callbackList = []
	for aNode in graphity.nodes(data=True):
		for call in aNode[1]['calls']:

			addr = ''
			# TODO consider this bad practise, do something smarter, not sure yet what,  consider _beginthread API etc. etc.
			# also, maybe this is fixed in radare later, so consider this code redundant by then
			if 'CreateThread' in call[1]:
				addr = getCallback(call[0], 3)

			if 'SetWindowsHookEx' in call[1]:
				addr = getCallback(call[0], 2)

			if addr in graphity:
					graphity.node[addr]['type'] = "Callback"
					graphity.add_edge(aNode[0], addr, pos=call[0], calltype="callback")


# Parsing the handler offset out of the function arguments
def getCallback(call, argcount):

	# simplistic: walk up the code until xref to code is found, works as long as API only receives one code ref, works well with Windows APIs
	disasmMore = "pd -30 @" + call
	upwards = R2PY.cmd(disasmMore)

	for otherLine in reversed(upwards.splitlines()):
		if 'push' in otherLine:
			argcount = argcount - 1

		if not argcount:
			address = otherLine.split()[2]
			if 'fcn.' in address:
				return hex(int(address.split('.')[1], 16))
			else:
				return ''


def functionalityScan(graphity, pattern):

	# search is performed by defining "anchor" node, where initial pattern is found
	# search then moved from there 1 level up to search surrounding nodes (number of levels could be increased)
	# pattern lists for now are kept rather small
	# TODO determine distance between found patterns to see which functionalities lie close to each other
	patternNum = len(pattern)
	anchorList = []

	allCalls = nx.get_node_attributes(graphity, 'calls')

	for function in allCalls:
		for call in allCalls[function]:

			api = call[1]
			anchorpat = pattern[0]

			if anchorpat in api:
				if not filter(lambda daAnchor: daAnchor['address'] == function, anchorList):

					# maintain a dict of patterns per anchor to keep track of found patterns
					patternCheck = {}
					for item in pattern:
						patternCheck[item] = False
					patternCheck[anchorpat] = function

					anchorList.append({'address':function, 'patterns':patternCheck})

	# anchor nodes found and more than one pattern searched for
	if patternNum > 1 and len(anchorList) > 0:
		for anchor in anchorList:

			scanNodeForApi(anchor, anchor['address'], patternNum)
			if False in anchor['patterns'].values():

				anchorNeighbors = nx.all_neighbors(graphity, anchor['address'])
				for neighbor in anchorNeighbors:
					scanNodeForApi(anchor, neighbor, patternNum)

	return anchorList


# Search for a specific pattern within a node, orient by anchor pattern
def scanNodeForApi(anchor, seNode, patternNum):

	for patt in anchor['patterns']:

		# anchor has a dict that saves which patterns were found already
		for call in graphity.node[seNode]['calls']:
			api = call[1]

			# found a pattern in an api call, that hasnt been found before
			if patt in api and anchor['patterns'][patt] == False:
				anchor['patterns'][patt] = seNode

				if not False in anchor['patterns'].values():
					# all patterns found - done
					break


def TestEarth(filNam):
	global R2PY

	R2PY = r2pipe.open(filNam)

	# benchmarking :P
	bench = {}

	allAtts = getAllAttributes(filNam)

	print( '* %s R2 started analysis ' % str(datetime.now()))

	R2PY.cmd("e scr.color = false")
	R2PY.cmd("e asm.bytes = false")
	R2PY.cmd("e asm.lines = false")
	R2PY.cmd("e asm.fcnlines = false")
	R2PY.cmd("e asm.xrefs = false")
	R2PY.cmd("e asm.lbytes = false")
	R2PY.cmd("e asm.indentspace = 0")
	R2PY.cmd("e anal.autoname= false")

	R2PY.cmd("e anal.jmptbl = true")
	R2PY.cmd("e anal.hasnext = true")

	R2PY.cmd("aaa")
	R2PY.cmd("afr")
	R2PY.cmd("afr @@ sym*")

	# GRAPH CREATION
	graphity, debug = createSeGraph()

	# DLL PROCESSING
	if 'DLL' in allAtts['filetype']:
		analyzeExports(graphity)

	# thunkPruning
	thunkPruning(graphity)

	# handler tagging
	tagCallbacks(graphity)



os.environ["PATH"] = os.environ["PATH"] + ";C:\\Users\\rchateau\\AppData\\Local\\Programs\\radare2"


filNam = r"C:\Program Files (x86)\Google\Google Earth Pro\client\googleearth.exe"

TestEarth(filNam)