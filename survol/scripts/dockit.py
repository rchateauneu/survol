#!/usr/bin/env python

"""Monitors living processes and generates a dockerfile And much more."""

# NOTE: For convenience purpose, this script is standalone, and therefore quite big.
# Requires Python 2.7 and later.

__author__      = "Remi Chateauneu"
__copyright__   = "Primhill Computers, 2018"
__credits__ = ["","",""]
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Remi Chateauneu"
__email__ = "contact@primhillcomputers.com"
__status__ = "Development"

import cProfile
import re
import sys
import getopt
import os
import subprocess
import time
import signal
import inspect
import socket
import json
import atexit
import datetime
import shutil
import platform
import tempfile
try:
    import urllib2
except ImportError:
    import urllib.request as urllib2
import threading

try:
    # Optional: To add more information to processes etc...
    import psutil
except ImportError:
    pass

def Usage(exitCode = 1, errMsg = None):
    if errMsg:
        print(errMsg)

    progNam = sys.argv[0]
    print("DockIT: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                     This message.")
    print("  -v,--verbose                  Verbose mode (Cumulative).")
    print("  -w,--warning                  Display warnings (Cumulative).")
    print("  -s,--summary <CIM class>      Prints a summary at the end: Start end end time stamps, executable name,\n"
        + "                                loaded libraries, read/written/created files and timestamps, subprocesses tree.\n"
        + "                                Examples: -s 'Win32_LogicalDisk.DeviceID=\"C:\",Prop1=\"Value1\",Prop2=\"Value2\"'\n"
        + "                                          -s 'CIM_DataFile:Category=[\"Others\",\"Shared libraries\"]'" )
    print("  -D,--dockerfile               Generates a dockerfile.")
    print("  -p,--pid <pid>                Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON      Output format. Default is TXT.")
    print("  -F,--summary-format TXT|XML   Summary output format. Default is XML.")
    print("  -i,--input <file name>        trace command input file.")
    print("  -l,--log <filename prefix>    trace command log output file.\n")
    print("  -t,--tracer strace|ltrace|cdb command for generating trace log")
    print("  -S,--server <Url>             Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("")
    print("strace command: "+BuildSTraceCommand("<command>",None))
    print("                "+BuildSTraceCommand(None,"<pid>"))
    print("ltrace command: "+BuildLTraceCommand("<command>",None))
    print("                "+BuildLTraceCommand(None,"<pid>"))

# Example to create a new unit test:
# ./dockit.py -D -l UnitTests/mineit_firefox  -t  ltrace bash firefox

    sys.exit(exitCode)

################################################################################
# This is set by a signal handler when a control-C is typed.
# It then triggers a clean exit, and creation of output results.
# This allows to monitor a running process, just for a given time
# without stopping it.
G_Interrupt = False

################################################################################

def LogWindowsFileStream(extCommand,aPid):
    raise Exception("Not implemented yet")

def CreateFlowsFromWindowsLogger(verbose,logStream):
    raise Exception("Not implemented yet")

################################################################################

class ExceptionIsExit(Exception):
    pass

class ExceptionIsSignal(Exception):
    pass

################################################################################

# Parsing of the arguments of the systems calls printed by strace and ltrace.
# This starts immediately after an open parenthesis or bracket.
# It returns an index on the closing parenthesis, or equal to the string length.
# This is called for each line and is on the critical path.
def ParseCallArguments(strArgs,ixStart = 0):
    lenStr = len(strArgs)

    theResult = []
    finished = False
    inQuotes = False
    levelParent = 0
    isEscaped = False
    while ixStart < lenStr and strArgs[ixStart] == ' ': ixStart += 1
    ixCurr = ixStart

    ixUnfinished = strArgs.find("<unfinished ...>",ixStart)
    if ixUnfinished >= 0:
        lenStr = ixUnfinished

    hasOctal = False
    while (ixCurr < lenStr) and not finished:

        aChr = strArgs[ixCurr]
        ixCurr += 1

        if isEscaped:
            isEscaped = False
            continue

        if aChr == '\\':
            # TODO: This might be an octal number as in ltrace.
            #if (ixCurr == lenStr) or (strArgs[ixCurr] != '0'):
            isEscaped = True
            continue

        if aChr == '"':
            # TODO: ltrace does not escape double-quotes:
            #  "\001$\001$\001\026\001"\0015\001\n\001\r\001\r\001\f\001(\020",
            # "read@SYS(3, "" + str(row) + "\\n")\n\n", 4096)"
            inQuotes = not inQuotes
            continue

        if inQuotes:
            continue

        # This assumes that [] and {} are paired by strace so no need to check parity.
        if aChr in ['[','{']:
            if ixCurr == ixStart +1:
                objToAdd, ixStart = ParseCallArguments( strArgs, ixCurr)
                theResult.append( objToAdd )
                while ixStart < lenStr and strArgs[ixStart] in [' ',',']: ixStart += 1
                ixCurr = ixStart
                continue
            levelParent += 1
        elif aChr == '(':
            levelParent += 1
        elif aChr in [')',']','}']:
            levelParent -= 1
            if levelParent == -1:
                finished = True
                if ixCurr == ixStart +1:
                    continue
            else:
                continue

        if (aChr == ',' and levelParent == 0) or finished :
            while ixStart < lenStr and strArgs[ixStart] in [' ','"']: ixStart += 1
            ixEnd = ixCurr-2
            while strArgs[ixEnd] == '"' and ixStart <= ixEnd: ixEnd -= 1

            argClean = strArgs[ixStart:ixEnd + 1]
            # Special case due to truncated strings.
            # TODO: Should we truncate ? If read()/write'), we know what the length should be."
            if argClean.endswith('"...'):
                argClean = argClean[:-4] + "..."

            theResult.append( argClean )

            while ixCurr < lenStr and strArgs[ixCurr] == ' ': ixCurr += 1
            ixStart = ixCurr

    if (ixStart < lenStr) and not finished:
        while ixStart < lenStr and strArgs[ixStart] in [' ','"']: ixStart += 1
        ixEnd = lenStr-1
        while strArgs[ixEnd] in [',',')',']','}',' ','"'] and ixStart <= ixEnd: ixEnd -= 1

        argClean = strArgs[ixStart:ixEnd + 1]
        # Special case due to truncated strings.
        # TODO: Should we truncate ? If read()/write'), we know what the length should be."
        if argClean.endswith('"...'):
            argClean = argClean[:-4] + "..."
        theResult.append( argClean )

    return theResult,ixCurr

################################################################################

def TimeStampToStr(timStamp):
    # 0     tm_year     (for example, 1993)
    # 1     tm_mon      range [1, 12]
    # 2     tm_mday     range [1, 31]
    # 3     tm_hour     range [0, 23]
    # 4     tm_min      range [0, 59]
    # 5     tm_sec      range [0, 61]; see (2) in strftime() description
    # 6     tm_wday     range [0, 6], Monday is 0
    # 7     tm_yday     range [1, 366]
    # 8     tm_isdst    0, 1 or -1; see below

    # Today's date can change so we can reproduce a run.
    if timStamp:
        return G_Today + " " + timStamp
    else:
        return G_Today + " 00:00:00.000000"

def IsTimeStamp(attr,attrVal):
    return attr.find("Date") > 0 or attr.find("Time") > 0

def IsCIM(attr,attrVal):
    return not callable(attrVal) and not attr.startswith("__") and not attr.startswith("m_")

# attr=AccessTime attrVal=1518262584.92 <type 'float'>
def TimeT_to_DateTime(stTimeT):
    # Or utcfromtimestamp
    return datetime.datetime.strftime( datetime.datetime.fromtimestamp(stTimeT), "%H:%M:%S:%f")

################################################################################

# Buffers transferred with read() and write() are parsed to detect information
# about the running applications. There can be several types of parsers,
# indexed by a descriptive key.
BufferScanners = {}

# This creates the SQL queries scanner, it needs Survol code.
try:

    sys.path.append("../..")
    from survol import lib_sql

    dictRegexSQL = lib_sql.SqlRegularExpressions()

    dictRegexSQLCompiled = {
        rgxKey : re.compile(dictRegexSQL[rgxKey], re.IGNORECASE)
        for rgxKey in dictRegexSQL
    }

    # This returns a list of SQL queries.
    def RawBufferSqlQueryScanner(aBuffer):
        # The regular expressions are indexed with a key such as "INSERT", "SELECT" etc...
        # which gives a hint about what the query does.
        # This creates a dictionary mapping the RDF property to the compiled regular expression.
        # Also, the regular expressions are compiled for better performance.

        lstQueries = []

        for rgxKey in dictRegexSQLCompiled:
            compiledRgx = dictRegexSQLCompiled[rgxKey]
            matchedSqls = compiledRgx.findall(aBuffer)
            if matchedSqls:
                lstQueries += matchedSqls

        # TODO: For the moment, we just print the query. How can it be related to a database ?
        # How can we get the database connection ?
        # If attaching to a running process, this is even impossible.
        # TODO: We can create symbolic database connection: At least we known the server name.
        # We can associate one connection to each socket or pipe where a SQL query could be found.
        # ... possibly list the connections as CIM objects.
        # An extra regular expression on the buffer, or some test on the SQL query,
        # might imply the database type. This is not very important because the database connection
        # is an obvious information
        # for the user.
        return lstQueries

    BufferScanners["SqlQuery"] = RawBufferSqlQueryScanner
except ImportError:
    print("Cannot import optional module lib_sql")
    pass

################################################################################

def DecodeOctalEscapeSequence(aBuffer):
    # An octal escape sequence consists of \ followed by one, two, or three octal digits.
    # The octal escape sequence ends when it either contains three octal digits already,
    # or the next character is not an octal digit.
    # For example, \11 is a single octal escape sequence denoting a byte with numerical value 9 (11 in octal),
    # rather than the escape sequence \1 followed by the digit 1.
    # However, \1111 is the octal escape sequence \111 followed by the digit 1.
    # In order to denote the byte with numerical value 1, followed by the digit 1,
    # one could use "\1""1", since C automatically concatenates adjacent string literals.
    # Note that some three-digit octal escape sequences may be too large to fit in a single byte;
    # this results in an implementation-defined value for the byte actually produced.
    # The escape sequence \0 is a commonly used octal escape sequence,
    # which denotes the null character, with value zero.
    # https://en.wikipedia.org/wiki/Escape_sequences_in_C

    # https://stackoverflow.com/questions/4020539/process-escape-sequences-in-a-string-in-python
    if (sys.version_info >= (3,)):
        decBuf = bytes(aBuffer, "utf-8").decode("unicode_escape")
    else:
        decBuf = aBuffer.decode('string_escape')
    return decBuf

# When strace or ltrace display a call to read() and write(), they also display
# a fragment of the transferred bytes. It is needed to try to rebuild the entire
# sequence between the opening and the closing, because some important information
# that we want to parse, might be truncated.
# Beware, there are severe limitations: The amount of displayed bytes is limited,
# and it does not take into account fseek().
class BufferConcatenator:
    def __init__(self):
        self.m_currentBuffer = None
        self.m_parsedData = None

    def AnalyseCompleteBuffer(self,aBuffer):
        for scannerKey in BufferScanners:
            scannerFunction = BufferScanners[scannerKey]

            # This returns a list of strings.
            # TODO: In a second stage, this will return CIM objects.
            lstResults = scannerFunction(aBuffer)

            if lstResults:
                if self.m_parsedData == None:
                    self.m_parsedData = {}
                if scannerKey in self.m_parsedData:
                    self.m_parsedData[scannerKey] += lstResults
                else:
                    self.m_parsedData[scannerKey] = lstResults


    def HasParsedData(self):
        return self.m_parsedData != None

    def ParsedDataToXML(self, strm, margin,direction):
        if self.m_parsedData:
            submargin = margin + "    "
            for scannerKey in self.m_parsedData:
                # TODO: Have a specific tag for the list.
                scannerKeySet = scannerKey + "_List"
                strm.write("%s<%s direction='%s'>\n" % ( margin, scannerKeySet, direction ) )
                scannerVal = self.m_parsedData[scannerKey]
                for scanResult in scannerVal:
                    strm.write("%s<%s>%s</%s>\n" % ( submargin, scannerKey, scanResult, scannerKey ) )
                strm.write("%s</%s>\n" % ( margin, scannerKeySet ) )


    # This receives all read() and write() buffers displayed by strace or ltrace,
    # decodes them and tries to rebuild a complete logical message if it seems
    # to be truncated.
    # It then analyses the logical pieces.
    def AppendIOBuffer(self,aFragment,szFragment = 0):
        decodedFragment = DecodeOctalEscapeSequence(aFragment)

        # Typical buffer size are multiple of 100x:
        #      256              100 #
        #      512              200 #
        #    12288             3000 #
        #    49152             c000 #
        #    65536            10000 #
        #   262144            40000 #

        isSegment = \
            ( ( szFragment % 0x100 == 0 ) and ( szFragment <= 0x1000) ) \
        or ( ( szFragment % 0x1000 == 0 ) and ( szFragment <= 0x10000) ) \
        or ( ( szFragment % 0x10000 == 0 ) and ( szFragment <= 0x100000) ) \
        or ( ( szFragment % 0x100000 == 0 )  )

        if isSegment and (szFragment == len(decodedFragment)):
            if self.m_currentBuffer:
                self.m_currentBuffer += decodedFragment
            else:
                self.m_currentBuffer = decodedFragment
        else:
            if self.m_currentBuffer:
                self.AnalyseCompleteBuffer(self.m_currentBuffer)
                # Reuse memory.
                del self.m_currentBuffer
                self.m_currentBuffer = None

            self.AnalyseCompleteBuffer(decodedFragment)


################################################################################

# Max bytes number when strace or ltrace display read() and write() calls.
G_StringSize = "500"

# This is a dictionary (indexed by processes) of dictionaries (indexed by files).
# It containes files accesses, which are object representing what happens
# to a file between its opening and closing by a process.
G_cacheFileAccesses = None

# This models an open/read-or-write/close access from a process to a file.
# The same process may access several times the same file,
# producing several FileAccess objects.
# This is displayed in XML as a single tag:
# <FileAccess OpenTime="" CloseTime="" etc... />
class FileAccess:
    def __init__(self,objProcess,objDataFile):
        self.OpenTime = None
        self.CloseTime = None
        self.m_objectCIM_Process = objProcess
        self.m_objectCIM_DataFile = objDataFile

        objProcess.m_ProcessFileAccesses.append(self)
        objDataFile.m_DataFileFileAccesses.append(self)

    def SetOpenTime(self, timeStamp):
        global G_cacheFileAccesses

        try:
            self.NumOpen += 1
        except AttributeError:
            self.NumOpen = 1
        if not self.OpenTime or (timeStamp < self.OpenTime):
            self.OpenTime = timeStamp

            if G_SameMachine:
                try:
                    filStat = os.stat( self.m_objectCIM_DataFile.Name )
                    self.OpenSize = filStat.st_size
                except:
                    pass

        # Strictly speaking, from now on, this is accessible from the cache.
        G_cacheFileAccesses[self.m_objectCIM_Process][self.m_objectCIM_DataFile] = self

    def SetCloseTime(self, timeStamp):
        global G_cacheFileAccesses

        # Maybe the file was never closed.
        if not getattr(self,"CloseTime",0) or (timeStamp < self.CloseTime):
            self.CloseTime = timeStamp

            if G_SameMachine:
                try:
                    filStat = os.stat( self.m_objectCIM_DataFile.Name )
                    self.CloseSize = filStat.st_size
                except:
                    pass

        # Then remove the object from the cache so it cannot be returned
        # anymore from this process and this file because it is closed.
        del G_cacheFileAccesses[self.m_objectCIM_Process][self.m_objectCIM_DataFile]

    def AnalyseNewBuffer(self,isRead,szBuffer,aBuffer):
        if not aBuffer:
            return

        # This does not apply to files.
        if self.m_objectCIM_DataFile.IsPlainFile():
            return

        if isRead:
            try:
                self.m_bufConcatRead
            except AttributeError:
                self.m_bufConcatRead = BufferConcatenator()
            concatBuf = self.m_bufConcatRead
        else:
            try:
                self.m_bufConcatWrite
            except AttributeError:
                self.m_bufConcatWrite = BufferConcatenator()
            concatBuf = self.m_bufConcatWrite

        try:
            concatBuf.AppendIOBuffer(aBuffer,szBuffer)
        except:
            # Example: '[pid  5602] 19:59:20.590740 <... read resumed> "... end of read() content"..., 32768) = 4096 <0.037642>'
            sys.stdout.write("Cannot parse:%s szBuffer=%s\n"%(aBuffer,szBuffer))
            exit(1)

    def SetRead(self,bytesRead,bufferRead):
        try:
            self.NumReads += 1
        except AttributeError:
            self.NumReads = 1
        try:
            self.BytesRead += bytesRead
        except AttributeError:
            self.BytesRead = bytesRead
        self.AnalyseNewBuffer(True,bytesRead,bufferRead)

    def SetWritten(self, bytesWritten,bufferWrite):
        try:
            self.NumWrites += 1
        except AttributeError:
            self.NumWrites = 1
        try:
            self.BytesWritten += bytesWritten
        except AttributeError:
            self.BytesWritten = bytesWritten
        self.AnalyseNewBuffer(False,bytesWritten,bufferWrite)

    def TagXML(self,strm,margin,displayedFromProcess):
        strm.write("%s<Access" % ( margin ) )

        if displayedFromProcess:
            if self.m_objectCIM_Process:
                strm.write(" Process='%s'" % ( self.m_objectCIM_Process.Handle ) )
        else:
            if self.m_objectCIM_DataFile:
                strm.write(" File='%s'" % ( self.m_objectCIM_DataFile.Name ) )

        if self.OpenTime:
            strm.write(" OpenTime='%s'" % TimeStampToStr( self.OpenTime ) )
        if getattr(self,'OpenSize',0):
            strm.write(" OpenSize='%s'" % ( self.OpenSize ) )
        if self.CloseTime:
            strm.write(" CloseTime='%s'" % TimeStampToStr( self.CloseTime ) )
        if getattr(self,'CloseSize',0):
            strm.write(" CloseSize='%s'" % ( self.CloseSize ) )
        if getattr(self,'NumReads',0):
            strm.write(" NumReads='%s'" % ( self.NumReads ) )
        if getattr(self,'BytesRead',0):
            strm.write(" BytesRead='%s'" % ( self.BytesRead ) )
        if getattr(self,'NumWrites',0):
            strm.write(" NumWrites='%s'" % ( self.NumWrites ) )
        if getattr(self,'BytesWritten',0):
            strm.write(" BytesWritten='%s'" % ( self.BytesWritten ) )

        accRead = getattr(self,'m_bufConcatRead',None)
        accWrite = getattr(self,'m_bufConcatWrite',None)

        if (accRead and accRead.HasParsedData() ) or (accWrite and accWrite.HasParsedData() ):
            strm.write(" >\n" )

            submargin = margin + "    "
            if accRead and accRead.HasParsedData():
                accRead.ParsedDataToXML(strm, submargin,"Read")
            if accWrite and accWrite.HasParsedData():
                accWrite.ParsedDataToXML(strm, submargin,"Write")

            strm.write("%s</Access>\n" % ( margin ) )
        else:
            strm.write(" />\n" )


    @staticmethod
    def LookupFileAccess(objProcess,objDataFile):
        global G_cacheFileAccesses

        try:
            filAcc = G_cacheFileAccesses[objProcess][objDataFile]
        except KeyError:
            filAcc = FileAccess(objProcess,objDataFile)
            try:
                G_cacheFileAccesses[objProcess][objDataFile] = filAcc
            except KeyError:
                G_cacheFileAccesses[objProcess] = {objDataFile : filAcc}
        return filAcc

    @staticmethod
    def VectorToXML(strm,vecFilesAccesses,margin,displayedFromProcess):
        if not vecFilesAccesses:
            return
        subMargin = margin + "    "
        strm.write("%s<FileAccesses>\n" % ( margin ) )
        for filAcc in vecFilesAccesses:
            filAcc.TagXML(strm,subMargin,displayedFromProcess)
        strm.write("%s</FileAccesses>\n" % ( margin ) )


################################################################################

# This objects groups triples to send to the HTTP server,
# and periodically wakes up to send them.
class HttpTriplesClient(object):
    def __init__(self):
        self.m_sharedLock = threading.Lock()
        self.m_listTriples = []
        aThrd = threading.Thread(target = self.run)
        # If leaving too early, some data might be lost.
        aThrd.daemon = True
        aThrd.start()
        self.m_valid = True

    def run(self):
        while True:
            # TODO: Wait the same delay before leaving the program.
            time.sleep(2.0)
            self.m_sharedLock.acquire()
            numTriples = len(self.m_listTriples)
            if numTriples:
                strToSend = json.dumps(self.m_listTriples)
                if sys.version_info >= (3,):
                    assert isinstance(strToSend, str)
                    strToSend = strToSend.encode('utf-8')
                    assert isinstance(strToSend, bytes)
                else:
                    assert isinstance(strToSend, str)
                self.m_listTriples = []
            else:
                strToSend = None
            # Immediately unlocked so no need to wait for the server.
            self.m_sharedLock.release()

            if strToSend:
                try:
                    sys.stdout.write("About to write to:%s %d bytes\n" % (G_UpdateServer, len(strToSend)))
                    sys.stdout.flush()
                    req = urllib2.Request(G_UpdateServer)
                    req.add_header('Content-Type', 'application/json')

                    sys.stdout.write("Tm=%f Sending %d triples to %s\n" % (time.time(), numTriples, G_UpdateServer))
                    sys.stdout.flush()

                    # POST data should be bytes, an iterable of bytes, or a file object. It cannot be of type str
                    response = urllib2.urlopen(req, data=strToSend, timeout=5.0)

                    sys.stdout.write("Tm=%f Reading response from %s\n"% ( time.time(), G_UpdateServer))
                    sys.stdout.flush()
                    srvOut = response.read()
                except:
                    self.m_valid = False
                    raise


    def AddDataToSend(self,jsonTriple):
        if self.m_valid and G_UpdateServer:
            self.m_sharedLock.acquire()
            self.m_listTriples.append(jsonTriple)
            self.m_sharedLock.release()

# This is the Survol server which is notified of all updates
# of CIM objects. These updates can then be displayed in Survol Web clients.
# It must be a plain Web server to be hosted by Apache or IIS.
G_UpdateServer = None
G_httpClient = HttpTriplesClient()

################################################################################


# This is the base class of all CIM_xxx classes. It does the serialization
# into XML and also sends updates events to the Survol server if there is one.
class CIM_XmlMarshaller:
    def __init__(self):
        pass

    def PlainToXML(self,strm,subMargin):
        try:
            # Optional members order.
            attrExtra = self.__class__.m_AttrsPriorities
        except AttributeError:
            attrExtra = []

        start = len(attrExtra)
        enumAttrs = {}
        for elt in dir(self):
            enumAttrs[ elt ] = start
            start += 1

        start = 0
        for elt in attrExtra:
            enumAttrs[ elt ] = start
            start += 1

        dictAttrs = dict((val,key) for (key,val) in enumAttrs.items())
        for idx in sorted(dictAttrs.keys()):
            attr = dictAttrs[idx]
            try:
                attrVal = getattr(self,attr)
            except AttributeError:
                continue
            if IsCIM(attr,attrVal):
                # FIXME: Not very reliable.
                if IsTimeStamp(attr,attrVal):
                    attrVal = TimeStampToStr(attrVal)
                if attrVal:
                    # No need to write empty strings.
                    strm.write("%s<%s>%s</%s>\n" % ( subMargin, attr, attrVal, attr ) )

    def HttpUpdateRequest(self,**objJson):
        G_httpClient.AddDataToSend(objJson)

    def SendUpdateToServer(self, attrNam, oldAttrVal, attrVal):
        # These are the properties which uniquely define the object.
        # There are always sent even if they did not change,
        # otherwise the object could not be identified.
        theSubjMoniker = self.GetMonikerSurvol()

        # TODO: If the attribute is part of the ontology, just inform about the object creation.
        # TODO: Some attributes could be the moniker of another object.
        # TODO: AND THEREFORE, SEND LINKS, NOT ONLY LITERALS !!!
        # OTHERWISE NO EDGES !!

        if oldAttrVal and isinstance( oldAttrVal, CIM_XmlMarshaller):
            objMonikerOld = oldAttrVal.GetMonikerSurvol()
            attrNamDelete = attrNam + "?predicate_delete"
            self.HttpUpdateRequest(subject=theSubjMoniker,predicate=attrNam,object=objMonikerOld )


        # For example a file being opened by a process, or a process started by a user etc...
        if isinstance( attrVal, CIM_XmlMarshaller):
            objMoniker = attrVal.GetMonikerSurvol()
            self.HttpUpdateRequest(subject=theSubjMoniker,predicate=attrNam,object=objMoniker)
        else:
            self.HttpUpdateRequest(subject=theSubjMoniker,predicate=attrNam,object=attrVal)

    # Any object change is broadcast to a Survol server.
    def __setattr__(self, attrNam, attrVal):
        # First, change the value, because it might be needed to calculate the moniker.

        try:
            oldAttrVal = self.__dict__[attrNam]
        except:
            oldAttrVal = None

        self.__dict__[attrNam] = attrVal

        #https://stackoverflow.com/questions/8600161/executing-periodic-actions-in-python

        if G_UpdateServer:
            if oldAttrVal != attrVal:
                if IsCIM(attrNam,attrVal):
                    self.SendUpdateToServer(attrNam, oldAttrVal, attrVal)

    @classmethod
    def DisplaySummary(theClass,fdSummaryFile,cimKeyValuePairs):
        pass

    @classmethod
    def XMLSummary(theClass,fdSummaryFile,cimKeyValuePairs):
        namClass = theClass.__name__
        margin = "    "
        subMargin = margin + margin
        for objPath,objInstance in sorted( G_mapCacheObjects[namClass].items() ):
            fdSummaryFile.write("%s<%s>\n" % ( margin, namClass ) )
            objInstance.PlainToXML(fdSummaryFile,subMargin)
            fdSummaryFile.write("%s</%s>\n" % ( margin, namClass ) )

    @classmethod
    def CreateMonikerKey(theClass,*args):
        # The input arguments must be in the same order as the ontology.
        #sys.stdout.write("CreateMonikerKey %s %s %s\n"%(theClass.__name__,str(theClass.m_Ontology),str(args)))
        mnk = theClass.__name__ + "." + ",".join( '%s="%s"' % (k,v) for k,v in zip(theClass.m_Ontology,args) )
        #sys.stdout.write("CreateMonikerKey mnk=%s\n"%mnk)
        return mnk

    # JSON escapes special characters in strings.
    def GetMonikerSurvol(self):
        dictMonik = { "entity_type": self.__class__.__name__}
        for k in self.m_Ontology:
            dictMonik[k] = getattr(self,k)
        return dictMonik

    def __repr__(self):
        mnk = self.__class__.__name__ + "." + ",".join( '%s="%s"' % (k,getattr(self,k)) for k in self.m_Ontology )
        return "%s" % mnk


################################################################################

# The CIM_xxx classes are taken from Common Information Model standard.
# They share some properties and are adding more.

# class CIM_ComputerSystem : CIM_System
# {
#   string   Caption;
#   string   Description;
#   datetime InstallDate;
#   string   Status;
#   string   CreationClassName;
#   string   Name;
#   string   PrimaryOwnerContact;
#   string   PrimaryOwnerName;
#   string   Roles[];
#   string   NameFormat;
# }
class CIM_ComputerSystem (CIM_XmlMarshaller,object):
    def __init__(self,hostname):
        super( CIM_ComputerSystem,self).__init__()
        self.Name = hostname.lower() # This is a convention.

        if not G_ReplayMode and psutil:
            vm = psutil.virtual_memory()
            self.VirtualMemoryTotal = vm[0]
            self.VirtualMemoryAvailable = vm[1]
            self.VirtualMemoryUsed = vm[3]
            self.VirtualMemoryFree = vm[4]

            try:
                cf = psutil.cpu_freq()
                if cf:
                    self.CpuCurrent = cf[0]
                    self.CpuMinimum = cf[1]
                    self.CpuMaximum = cf[2]
            except AttributeError:
                pass

    m_Ontology = ['Name']
#
# class CIM_OperatingSystem : CIM_LogicalElement
# {
#   string   Caption;
#   string   CreationClassName;
#   string   CSCreationClassName;
#   string   CSName;
#   sint16   CurrentTimeZone;
#   string   Description;
#   boolean  Distributed;
#   uint64   FreePhysicalMemory;
#   uint64   FreeSpaceInPagingFiles;
#   uint64   FreeVirtualMemory;
#   datetime InstallDate;
#   datetime LastBootUpTime;
#   datetime LocalDateTime;
#   uint32   MaxNumberOfProcesses;
#   uint64   MaxProcessMemorySize;
#   string   Name;
#   uint32   NumberOfLicensedUsers;
#   uint32   NumberOfProcesses;
#   uint32   NumberOfUsers;
#   uint16   OSType;
#   string   OtherTypeDescription;
#   uint64   SizeStoredInPagingFiles;
#   string   Status;
#   uint64   TotalSwapSpaceSize;
#   uint64   TotalVirtualMemorySize;
#   uint64   TotalVisibleMemorySize;
#   string   Version;
# };
class CIM_OperatingSystem (CIM_XmlMarshaller,object):
    def __init__(self):
        super( CIM_OperatingSystem,self).__init__()

        if not G_ReplayMode:
            self.OSType = sys.platform
            self.Name = os.name
            self.System = platform.system()
            self.Release = platform.release()
            self.Platform = platform.platform()

    m_Ontology = []
#
# class CIM_NetworkAdapter : CIM_LogicalDevice
# {
#   boolean  AutoSense;
#   uint16   Availability;
#   string   Caption;
#   uint32   ConfigManagerErrorCode;
#   boolean  ConfigManagerUserConfig;
#   string   CreationClassName;
#   string   Description;
#   string   DeviceID;
#   boolean  ErrorCleared;
#   string   ErrorDescription;
#   datetime InstallDate;
#   uint32   LastErrorCode;
#   uint64   MaxSpeed;
#   string   Name;
#   string   NetworkAddresses[];
#   string   PermanentAddress;
#   string   PNPDeviceID;
#   uint16   PowerManagementCapabilities[];
#   boolean  PowerManagementSupported;
#   uint64   Speed;
#   string   Status;
#   uint16   StatusInfo;
#   string   SystemCreationClassName;
#   string   SystemName;
# };
class CIM_NetworkAdapter (CIM_XmlMarshaller,object):
    def __init__(self,address):
        super( CIM_NetworkAdapter,self).__init__()
        self.Name = address
        self.PermanentAddress = address

    m_Ontology = ['Name']

#class CIM_Process : CIM_LogicalElement
#{
#  string   Caption;
#  string   CreationClassName;
#  datetime CreationDate;
#  string   CSCreationClassName;
#  string   CSName;
#  string   Description;
#  uint16   ExecutionState;
#  string   Handle;
#  datetime InstallDate;
#  uint64   KernelModeTime;
#  string   Name;
#  string   OSCreationClassName;
#  string   OSName;
#  uint32   Priority;
#  string   Status;
#  datetime TerminationDate;
#  uint64   UserModeTime;
#  uint64   WorkingSetSize;
#};
class CIM_Process (CIM_XmlMarshaller,object):
    def __init__(self,procId):
        super( CIM_Process,self).__init__()

        # sys.stdout.write("CIM_Process procId=%s\n"%procId)

        # BY CONVENTION, SOME MEMBERS MUST BE DISPLAYED AND FOLLOW CIM CONVENTION.
        self.Handle = procId
        self.m_parentProcess = None
        self.m_subProcesses = set()
        self.CreationDate = None
        self.TerminationDate = None

        # This contains all the files objects accessed by this process.
        # It is used when creating a DockerFile.
        # It is a set, so each file appears only once.
        self.m_ProcessFileAccesses = []

        # TODO: ADD AN ARRAY OF CIM_DataFile
        # AND THE ATTRIBUTES COULD CONTAIN THE DATA OF m_ProcessFileAccesses ???

        if not G_ReplayMode:
            # Maybe this cannot be accessed.
            if sys.platform.startswith("linux"):
                filnamEnviron = "/proc/%d/environ" % self.Handle
                try:
                    fdEnv = open(filnamEnviron)
                    arrEnv = fdEnv.readline().split('\0')
                    self.EnvironmentVariables = {}
                    for onePair in fdEnv.readline().split('\0'):
                        if onePair:
                            ixEq = onePair.find("=")
                            if ixEq > 0:
                                envKey = onePair[:ixEq]
                                envVal = onePair[ixEq+1:]
                                self.EnvironmentVariables[envKey] = envVal
                    fdEnv.close()
                except:
                    pass

        if not G_ReplayMode and psutil:
            try:
                # FIXME: If rerunning a simulation, this does not make sense.
                # Same for CIM_DataFile when this is not the target machine.
                procObj = psutil.Process(procId)
            except:
                # Maybe this is replaying a former session and in this case,
                # the process is not there anymore.
                procObj = None
        else:
            procObj = None

        if procObj:
            try:
                self.Name = procObj.name()
                execFilNam = procObj.exe()
                execFilObj = CreateObjectPath(CIM_DataFile,execFilNam)
                self.SetExecutable( execFilObj )
            except:
                self.Name = None

            try:
                # Maybe the process has exit.
                self.Username = procObj.username()
                self.Priority = procObj.nice()
            except:
                pass

            try:
                self.CurrentDirectory = procObj.cwd()
            except:
                 # psutil.ZombieProcess process still exists but it's a zombie
                 # Another possibility would be to use the parent process.
                self.CurrentDirectory = G_CurrentDirectory

        else:
            if procId > 0:
                self.Name = "pid=%s" % procId
            else:
                self.Name = ""
            # TODO: This could be deduced with calls to setuid().
            self.Username = ""
            # TODO: This can be partly deduced with calls to chdir() etc...
            # so it would not be necessary to install psutil.
            self.CurrentDirectory = G_CurrentDirectory
            self.Priority = 0

        # If this process appears for the first time and there is only
        # one other process, then it is its parent.
        # It helps if the first vfork() is never finished,
        # and if we did not get the main process id.
        try:
            mapProcs = G_mapCacheObjects[CIM_Process.__name__]
            keysProcs = list(mapProcs.keys())
            if len(keysProcs) == 1:
                # We are about to create the second process.

                # CIM_Process.Handle="29300"
                firstProcId = keysProcs[0]
                firstProcObj = mapProcs[ firstProcId ]
                if firstProcId != ( 'CIM_Process.Handle="%s"' % firstProcObj.Handle ):
                    raise Exception("Inconsistent procid:%s != %s" % (firstProcId, firstProcObj.Handle) )

                if firstProcObj.Handle == procId:
                    raise Exception("Duplicate procid:%s"%procId)
                self.SetParentProcess( firstProcObj )
        except KeyError:
            # This is the first process.
            pass

    m_Ontology = ['Handle']

    @classmethod
    def DisplaySummary(theClass,fdSummaryFile,cimKeyValuePairs):
        fdSummaryFile.write("Processes:\n")
        for objPath,objInstance in sorted( G_mapCacheObjects[CIM_Process.__name__].items() ):
            # sys.stdout.write("Path=%s\n"%objPath)
            objInstance.Summarize(fdSummaryFile)
        fdSummaryFile.write("\n")

    m_AttrsPriorities = ["Handle","Name","CommandLine","CreationDate","TerminationDate","Priority"]

    def XMLOneLevelSummary(self,strm,margin="    "):
        self.m_isVisited = True
        strm.write("%s<CIM_Process Handle='%s'>\n" % ( margin, self.Handle) )
        
        subMargin = margin + "    "

        self.PlainToXML(strm,subMargin)

        FileAccess.VectorToXML(strm,self.m_ProcessFileAccesses,subMargin,False)

        for objInstance in self.m_subProcesses:
            objInstance.XMLOneLevelSummary(strm,subMargin)
        strm.write("%s</CIM_Process>\n" % ( margin ) )

    @staticmethod
    def TopProcessFromProc(objInstance):
        """This returns the top-level parent of a process."""
        while True:
            parentProc = objInstance.m_parentProcess
            if not parentProc: return objInstance
            objInstance = parentProc

    @staticmethod
    def GetTopProcesses():
        """This returns a list of top-level processes, which have no parents."""

        # This contains all subprocesses.
        setSubProcs = set()
        for objPath,objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            for oneSub in objInstance.m_subProcesses:
                setSubProcs.add(oneSub)

        lstTopLvl = []
        for objPath,objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            if objInstance not in setSubProcs:
                lstTopLvl.append(objInstance)
        return lstTopLvl

    # When parsing the last system call, it sets the termination date for all processes.
    @staticmethod
    def GlobalTerminationDate(timeEnd):
        for objPath,objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            if not objInstance.TerminationDate:
                objInstance.TerminationDate = timeEnd

    @classmethod
    def XMLSummary(theClass,fdSummaryFile,cimKeyValuePairs):
        # Find unvisited processes. It does not start from G_top_ProcessId
        # because maybe it contains several trees, or subtrees were missed etc...
        for objPath,objInstance in sorted( G_mapCacheObjects[CIM_Process.__name__].items() ):
            try:
                objInstance.m_isVisited
                continue
            except AttributeError:
                pass

            topObjProc = CIM_Process.TopProcessFromProc(objInstance)

            topObjProc.XMLOneLevelSummary(fdSummaryFile)

    # In text mode, with no special formatting.
    def Summarize(self,strm):
        strm.write("Process id:%s\n" % self.Handle )
        try:
            if self.Executable:
                strm.write("    Executable:%s\n" % self.Executable )
        except AttributeError:
            pass
        if self.CreationDate:
            strStart = TimeStampToStr( self.CreationDate )
            strm.write("    Start time:%s\n" % strStart )
        if self.TerminationDate:
            strEnd = TimeStampToStr( self.TerminationDate )
            strm.write("    End time:%s\n" % strEnd )
        if self.m_parentProcess:
            strm.write("    Parent:%s\n" % self.m_parentProcess.Handle )

    def SetParentProcess(self, objCIM_Process):
        # sys.stdout.write("SetParentProcess proc=%s parent=%s\n" % ( self.Handle, objCIM_Process.Handle ) )
        if int(self.Handle) == int(objCIM_Process.Handle):
            raise Exception("Self-parent")
        self.m_parentProcess = objCIM_Process
        objCIM_Process.m_subProcesses.add(self)

    def AddParentProcess(self, timeStamp, objCIM_Process):
        self.SetParentProcess( objCIM_Process )
        self.CreationDate = timeStamp

    def WaitProcessEnd(self, timeStamp, objCIM_Process):
        # sys.stdout.write("WaitProcessEnd: %s linking to %s\n" % (self.Handle,objCIM_Process.Handle))
        self.TerminationDate = timeStamp
        if not self.m_parentProcess:
            self.SetParentProcess( objCIM_Process )
            # sys.stdout.write("WaitProcessEnd: %s not linked to %s\n" % (self.Handle,objCIM_Process.Handle))
        elif self.m_parentProcess != objCIM_Process:
            # sys.stdout.write("WaitProcessEnd: %s not %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass
        else:
            # sys.stdout.write("WaitProcessEnd: %s already linked to %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass

    def SetExecutable(self,objCIM_DataFile) :
        assert( isinstance(objCIM_DataFile, CIM_DataFile) )
        self.Executable = objCIM_DataFile.Name
        self.m_ExecutableObject = objCIM_DataFile

    def SetCommandLine(self,lstCmdLine) :
        # TypeError: sequence item 7: expected string, dict found
        if lstCmdLine:
            self.CommandLine = " ".join( [ str(elt) for elt in lstCmdLine ] )
            # The command line as a list is needed by Dockerfile.
            self.m_commandList = lstCmdLine

    def GetCommandLine(self):
        try:
            if self.CommandLine:
                return self.CommandLine
        except AttributeError:
            pass

        try:
            commandLine = self.Executable
        except AttributeError:
            commandLine = ""
        return commandLine
        
    def GetCommandList(self):
        try:
            if self.m_commandList:
                return self.m_commandList
        except AttributeError:
            pass

        try:
            commandList = [ self.Executable ]
        except AttributeError:
            commandList = []
        return commandList

    def SetThread(self):
        self.IsThread = True

    # Some system calls are relative to the current directory.
    # Therefore, this traces current dir changes due to system calls.
    def SetProcessCurrentDir(self,currDirObject):
        self.CurrentDirectory = currDirObject.Name

    def GetProcessCurrentDir(self):
        try:
            return self.CurrentDirectory
        except AttributeError:
            # Maybe it could not be get because the process left too quickly.
            return "UnknownCwd"


    # This returns an object indexed by the file name and the process id.
    # A file might have been opened several times by the same process.
    # Therefore, once a file has been closed, the associated file access
    # cannot be returned again.
    def GetFileAccess(self, objCIM_DataFile):
        filAcc = FileAccess.LookupFileAccess(self,objCIM_DataFile)
        return filAcc


# Other tools to consider:
# dtrace and blktrac and valgrind
# http://www.brendangregg.com/ebpf.html

# class CIM_DataFile : CIM_LogicalFile
# {
  # string   Caption;
  # string   Description;
  # datetime InstallDate;
  # string   Status;
  # uint32   AccessMask;
  # boolean  Archive;
  # boolean  Compressed;
  # string   CompressionMethod;
  # string   CreationClassName;
  # datetime CreationDate;
  # string   CSCreationClassName;
  # string   CSName;
  # string   Drive;
  # string   EightDotThreeFileName;
  # boolean  Encrypted;
  # string   EncryptionMethod;
  # string   Name;
  # string   Extension;
  # string   FileName;
  # uint64   FileSize;
  # string   FileType;
  # string   FSCreationClassName;
  # string   FSName;
  # boolean  Hidden;
  # uint64   InUseCount;
  # datetime LastAccessed;
  # datetime LastModified;
  # string   Path;
  # boolean  Readable;
  # boolean  System;
  # boolean  Writeable;
  # string   Manufacturer;
  # string   Version;
# };
class CIM_DataFile (CIM_XmlMarshaller,object):
    def __init__(self,pathName):
        super( CIM_DataFile,self).__init__()

        # https://msdn.microsoft.com/en-us/library/aa387236(v=vs.85).aspx
        # The Name property is a string representing the inherited name
        # that serves as a key of a logical file instance within a file system.
        # Full path names should be provided.

        # TODO: When the name contains "<" or ">" it cannot be properly displayed in SVG.
        # TODO: Also, names like "UNIX:" or "TCP:" should be processed a special way.
        self.Name = pathName
        # File name without the file name extension. Example: "MyDataFile"
        try:
            basNa = os.path.basename(pathName)
            # There might be several dots, or none.
            self.FileName = basNa.split(".")[0]
        except:
            pass
        self.Category = PathCategory(pathName)

        self.m_DataFileFileAccesses = []

        # Some information are meaningless because they vary between executions.
        if G_SameMachine:
            try:
                objStat = os.stat(pathName)
            except:
                objStat = None

            if objStat:
                self.FileSize = objStat.st_size
                self.FileMode = objStat.st_mode
                self.Inode = objStat.st_ino
                self.DeviceId = objStat.st_dev
                self.HardLinksNumber = objStat.st_nlink
                self.OwnerUserId = objStat.st_uid
                self.OwnerGroupId = objStat.st_gid
                self.AccessTime = TimeT_to_DateTime(objStat.st_atime)
                self.ModifyTime = TimeT_to_DateTime(objStat.st_mtime)
                self.CreationTime = TimeT_to_DateTime(objStat.st_ctime)
                try:
                    # This does not exist on Windows.
                    self.DeviceType = objStat.st_rdev
                except AttributeError:
                    pass

                # This is on Windows only.
                # self.UserDefinedFlags = objStat.st_flags
                # self.FileCreator = objStat.st_creator
                # self.FileType = objStat.st_type

        # If this is a connected socket:
        # 'TCP:[54.36.162.150:37415->82.45.12.63:63708]'
        mtchSock = re.match(r"TCP:\[.*->(.*)\]", pathName)
        if mtchSock:
            self.SetAddrPort( mtchSock.group(1) )
        else:
            # 'TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]'
            mtchSock = re.match(r"TCPv6:\[.*->(.*)\]", pathName)
            if mtchSock:
                self.SetAddrPort( mtchSock.group(1) )

    m_Ontology = ['Name']

    # This creates a map containing all detected files. This map is indexed
    # by an informal file category: DLL, data file etc...
    @staticmethod
    def SplitFilesByCategory():
        try:
            mapFiles = G_mapCacheObjects[CIM_DataFile.__name__].items()
        except KeyError:
            return {}

        # TODO: Find a way to define the presentation as a parameter.
        # Maybe we can use the list of keys: Just mentioning a property
        # means that a sub-level must be displayed.
        mapOfFilesMap = { rgxTuple[0] : {} for rgxTuple in G_lstFilters }

        # objPath = 'CIM_DataFile.Name="/usr/lib64/libcap.so.2.24"'
        for objPath,objInstance in mapFiles:
            mapOfFilesMap[ objInstance.Category ][ objPath ] = objInstance
        return mapOfFilesMap
        
    @classmethod
    def DisplaySummary(theClass,fdSummaryFile,cimKeyValuePairs):
        fdSummaryFile.write("Files:\n")
        mapOfFilesMap = CIM_DataFile.SplitFilesByCategory()

        try:
            filterCats = cimKeyValuePairs["Category"]
        except KeyError:
            filterCats = None

        for categoryFiles, mapFilesSub in sorted( mapOfFilesMap.items() ):
            fdSummaryFile.write("\n** %s\n"%categoryFiles)
            if filterCats and ( not categoryFiles in filterCats ): continue
            for objPath,objInstance in sorted( mapFilesSub.items() ):
                # sys.stdout.write("Path=%s\n"%objPath)
                objInstance.Summarize(fdSummaryFile)
        fdSummaryFile.write("\n")

    m_AttrsPriorities = ["Name","Category","SocketAddress"]

    def XMLDisplay(self,strm):
        margin = "        "
        strm.write("%s<CIM_DataFile Name='%s'>\n" % ( margin, self.Name) )
        
        subMargin = margin + "    "

        self.PlainToXML(strm,subMargin)

        FileAccess.VectorToXML(strm,self.m_DataFileFileAccesses,subMargin,True)

        strm.write("%s</CIM_DataFile>\n" % ( margin ) )

    @staticmethod
    def XMLCategorySummary(fdSummaryFile,mapFilesSub):
        for objPath,objInstance in sorted( mapFilesSub.items() ):
            # sys.stdout.write("Path=%s\n"%objPath)
            objInstance.XMLDisplay(fdSummaryFile)

    @classmethod
    def XMLSummary(theClass,fdSummaryFile,cimKeyValuePairs):
        """Top-level informations are categories of CIM_DataFile which are not technical
        but the regex-based filtering."""
        mapOfFilesMap = CIM_DataFile.SplitFilesByCategory()

        try:
            filterCats = cimKeyValuePairs["Category"]
        except KeyError:
            filterCats = None

        for categoryFiles, mapFilesSub in sorted( mapOfFilesMap.items() ):
            if len(mapFilesSub) == 0:
                # No need to write a category name if it is empty.
                continue

            fdSummaryFile.write("    <FilesCategory category='%s'>\n"%categoryFiles)
            if filterCats and ( not categoryFiles in filterCats ): continue
            CIM_DataFile.XMLCategorySummary(fdSummaryFile,mapFilesSub)
            fdSummaryFile.write("    </FilesCategory>\n")
        
    def Summarize(self,strm):
        try:
            # By default, this attribute is not set.
            if self.IsExecuted:
                return
        except AttributeError:
            pass
        strm.write("Path:%s\n" % self.Name )

        for filAcc in self.m_DataFileFileAccesses:

            if filAcc.OpenTime:
                strOpen = TimeStampToStr( filAcc.OpenTime )
                strm.write("  Open:%s\n" % strOpen )

                try:
                    strm.write("  Open times:%d\n" % filAcc.NumOpen )
                except AttributeError:
                    pass

            if filAcc.CloseTime:
                strClose = TimeStampToStr( filAcc.CloseTime )
                strm.write("  Close:%s\n" % strClose )

        # Only if this is a socket.
        # The original socket parameters might have been passed as a dict like:
        # "connect(6<UNIX:[587259]>, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110)"
        # But it might have been truncated like:
        # "['st_mode=S_IFREG|0644', 'st_size=121043', '...']"
        # So we are only sure that it is an array.
        try:
            for saKeyValue in self.SocketAddress:
                strm.write("    %s\n" % saKeyValue )
        except AttributeError:
            pass

    def SetIsExecuted(self) :
        self.IsExecuted = True

    # The input could be IPV4 or IPV6:
    # '82.45.12.63:63708]'
    # '::ffff:82.45.12.63:63703]'
    def SetAddrPort(self,pathIP):
        ixEq = pathIP.rfind(":")
        if ixEq < 0:
            self.Destination = pathIP
        else:
            self.Port = pathIP[ixEq+1:]
            addrIP = pathIP[:ixEq]
            try:
                self.Destination = socket.gethostbyaddr(addrIP)[0]
            except:
                self.Destination = addrIP


    @staticmethod
    def GetExposedPorts():
        """this is is the list of all ports numbers whihc have to be open."""

        try:
            mapFiles = G_mapCacheObjects[CIM_DataFile.__name__].items()
        except KeyError:
            return

        setPorts = set()
        for objPath,objInstance in mapFiles:
            try:
                setPorts.add( objInstance.Port )
            except AttributeError:
                pass
        return setPorts

    m_nonFilePrefixes = ["UNIX:","TCP:","TCPv6:","NETLINK:","pipe:","UDP:","UDPv6:",]

    def IsPlainFile(self):
        if self.Name:
            for pfx in CIM_DataFile.m_nonFilePrefixes:
                if self.Name.startswith(pfx):
                    return False
            return True
        return False


################################################################################

# This contains all CIM objects: CIM_Process, CIM_DataFile etc...
# and is used to generate the summary. Each time an object is created,
# updated or deleted, an event might be sent to a Survol server.
G_mapCacheObjects = None

################################################################################

# Environment variables actually access by processes.
# Used to generate a Dockerfile.
G_EnvironmentVariables = None

def CreateObjectPath(classModel, *ctorArgs):
    global G_mapCacheObjects
    try:
        mapObjs = G_mapCacheObjects[classModel.__name__]
    except KeyError:
        mapObjs = {}
        G_mapCacheObjects[classModel.__name__] = mapObjs

    objPath = classModel.CreateMonikerKey(*ctorArgs)
    try:
        theObj = mapObjs[objPath]
    except KeyError:
        theObj = classModel(*ctorArgs)
        mapObjs[objPath] = theObj
    return theObj


def ToObjectPath_CIM_Process(aPid):
    return CreateObjectPath(CIM_Process,aPid)

# It might be a Linux socket or an IP socket.
# The pid can be added so we know which process accesses this file.
def ToObjectPath_CIM_DataFile(pathName,aPid = None):
    #sys.stdout.write("ToObjectPath_CIM_DataFile pathName=%s aPid=%s\n" % ( pathName, str(aPid) ) )
    if aPid:
        # Maybe this is a relative file, and to make it absolute,
        # the process is needed.
        objProcess = ToObjectPath_CIM_Process(aPid)
        dirPath = objProcess.GetProcessCurrentDir()
    else:
        # At least it will suppress ".." etc...
        dirPath = ""

    pathName = ToAbsPath( dirPath, pathName )

    objDataFile = CreateObjectPath(CIM_DataFile,pathName)
    return objDataFile

# This is not a map, it is not sorted.
# It contains regular expression for classifying file names in categories:
# Shared libraries, source files, scripts, Linux pipes etc...
G_lstFilters = [
    ( "Shared libraries" , [
        r"^/usr/lib[^/]*/.*\.so",
        r"^/usr/lib[^/]*/.*\.so\..*",
        r"^/var/lib[^/]*/.*\.so",
        r"^/lib/.*\.so",
        r"^/lib64/.*\.so",
    ] ),
    ( "System config files" , [
        "^/etc/",
        "^/usr/share/fonts/",
        "^/usr/share/fontconfig/",
        "^/usr/share/fontconfig/",
        "^/usr/share/locale/",
        "^/usr/share/zoneinfo/",
    ] ),
    ( "Other libraries" , [
        "^/usr/share/",
        "^/usr/lib[^/]*/",
        "^/var/lib[^/]*/",
    ] ),
    ( "System executables" , [
        "^/bin/",
        "^/usr/bin[^/]*/",
    ] ),
    ( "Kernel file systems" , [
        "^/proc",
        "^/run",
    ] ),
    ( "Temporary files" , [
        "^/tmp/",
        "^/var/log/",
        "^/var/cache/",
    ] ),
    ( "Pipes and terminals" , [
        "^/sys",
        "^/dev",
        "^pipe:",
        "^socket:",
        "^UNIX:",
        "^NETLINK:",
    ] ),
    # TCP:[54.36.162.150:41039->82.45.12.63:63711]
    ( "Connected TCP sockets" , [
        r"^TCP:\[.*->.*\]",
        r"^TCPv6:\[.*->.*\]",
    ] ),
    ( "Other TCP/IP sockets" , [
        "^TCP:",
        "^TCPv6:",
        "^UDP:",
        "^UDPv6:",
    ] ),
    ( "Others" , [] ),
]

def PathCategory(pathName):
    """This match the path name againt the set of regular expressions
    defining broad categories of files: Sockets, libraries, temporary files...
    These categories are not technical but based on application best practices,
    rules of thumbs etc..."""
    for rgxTuple in G_lstFilters:
        for oneRgx in rgxTuple[1]:
            # If the file matches a regular expression,
            # then it is classified in this category.
            mtchRgx = re.match( oneRgx, pathName )
            if mtchRgx:
                return rgxTuple[0]
    return "Others"


# This receives an array of WMI/WBEM/CIM object paths:
# 'Win32_LogicalDisk.DeviceID="C:"'
# The values can be regular expressions.
# key-value pairs in the expressions are matched one-to-one with objects.

# Example: rgxObjectPath = 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
def ParseFilterCIM(rgxObjectPath):
    idxDot = rgxObjectPath.find(".")
    if idxDot < 0 :
        return ( rgxObjectPath, {} )

    objClassName = rgxObjectPath[:idxDot]

    # Maybe there is nothing after the dot.
    if idxDot == len(rgxObjectPath)-1:
        return ( objClassName, {} )

    strKeyValues = rgxObjectPath[idxDot+1:]

    # def toto(a='1',b='2')
    # >>> inspect.getargspec(toto)
    # ArgSpec(args=['a', 'b'], varargs=None, keywords=None, defaults=('1', '2'))
    tmpFunc = "def aTempFunc(%s) : pass" % strKeyValues

    # OK with Python 3
    exec(tmpFunc)
    local_temp_func = locals()["aTempFunc"]
    if sys.version_info >= (3,):
        tmpInsp = inspect.getfullargspec(local_temp_func)
    else:
        tmpInsp = inspect.getargspec(local_temp_func)
    arrArgs = tmpInsp.args
    arrVals = tmpInsp.defaults
    mapKeyValues = dict( zip(arrArgs, arrVals) )

    return ( objClassName, mapKeyValues )

# TODO: Probably not needed because noone wants this output format..
def GenerateSummaryTXT(mapParamsSummary, fdSummaryFile):
    for rgxObjectPath in mapParamsSummary:
        ( cimClassName, cimKeyValuePairs ) = ParseFilterCIM(rgxObjectPath)
        classObj = globals()[ cimClassName ]
        classObj.DisplaySummary(fdSummaryFile,cimKeyValuePairs)

# dated but exec, datedebut et fin exec, binaire utilise , librairies utilisees,
# fichiers cres, lus, ecrits (avec date+taille premiere action et date+taille derniere)  
# + arborescence des fils lances avec les memes informations 
def GenerateSummaryXML(mapParamsSummary,fdSummaryFile):
    fdSummaryFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fdSummaryFile.write('<Dockit>\n')
    if mapParamsSummary:
        for rgxObjectPath in mapParamsSummary:
            ( cimClassName, cimKeyValuePairs ) = ParseFilterCIM(rgxObjectPath)
            classObj = globals()[ cimClassName ]
            classObj.XMLSummary(fdSummaryFile,cimKeyValuePairs)
    fdSummaryFile.write('</Dockit>\n')

def GenerateSummary(mapParamsSummary, summaryFormat, outputSummaryFile):
    if summaryFormat == "TXT":
        summaryGenerator = GenerateSummaryTXT
    elif summaryFormat == "XML":
        # The output format is very different.
        summaryGenerator = GenerateSummaryXML
    elif summaryFormat == None:
        return
    else:
        raise Exception("Unsupported summary output format:%s"%summaryFormat)

    if outputSummaryFile:
        fdSummaryFile = open(outputSummaryFile, "w")
        sys.stdout.write("Creating summary file:%s\n"%outputSummaryFile)
    else:
        fdSummaryFile = sys.stdout

    summaryGenerator(mapParamsSummary,fdSummaryFile)

    if outputSummaryFile:
        sys.stdout.write("Closing summary file:%s\n"%outputSummaryFile)
        fdSummaryFile.close()

################################################################################

# See https://github.com/nbeaver/pip_file_lookup
pythonCache = {}

def PathToPythonModuleOneFileMakeCache(path):
    global pythonCache

    try:
        import lib_python
        pipInstalledDistributions = lib_python.PipGetInstalledDistributions()
        if pipInstalledDistributions == None:
            return
    except ImportError:
        return

    for dist in pipInstalledDistributions:
        # RECORDs should be part of .dist-info metadatas
        if dist.has_metadata('RECORD'):
            lines = dist.get_metadata_lines('RECORD')
            paths = [l.split(',')[0] for l in lines]
            distDirectory = dist.location
        # Otherwise use pip's log for .egg-info's
        elif dist.has_metadata('installed-files.txt'):
            paths = dist.get_metadata_lines('installed-files.txt')
            distDirectory = dist.egg_info
        else:
            distDirectory = None

        if distDirectory:
            for p in paths:
                normedPath = os.path.normpath( os.path.join(distDirectory, p) )
                try:
                    pythonCache[normedPath].append( dist )
                except KeyError:
                    pythonCache[normedPath] = [ dist ]

def PathToPythonModuleOneFile(path):
    try:
        return pythonCache[path]
    except KeyError:
        return []

def PathToPythonModuleOneFile_OldOldOldOld(path):
    try:
        import lib_python
        pipInstalledDistributions = lib_python.PipGetInstalledDistributions()
        if pipInstalledDistributions == None:
            return
    except ImportError:
        return

    for dist in pipInstalledDistributions:
        # RECORDs should be part of .dist-info metadatas
        if dist.has_metadata('RECORD'):
            lines = dist.get_metadata_lines('RECORD')
            paths = [l.split(',')[0] for l in lines]
            distDirectory = dist.location
        # Otherwise use pip's log for .egg-info's
        elif dist.has_metadata('installed-files.txt'):
            paths = dist.get_metadata_lines('installed-files.txt')
            distDirectory = dist.egg_info
        else:
            distDirectory = None

        if distDirectory:
            if path in [ os.path.normpath( os.path.join(distDirectory, p) ) for p in paths]:
                yield dist

# This takes as input a list of files, some of them installed by Python modules,
# and others having nothing to do with Python. It returns two data structures:
# - The set of unique Python modules, some files come from.
# - The remaining list of files, not coming from any Python module.
# This allow to reproduce an environment.
def FilesToPythonModules(unpackagedDataFiles):
    setPythonModules = set()
    unknownDataFiles = []

    for oneFilObj in unpackagedDataFiles:
        lstModules = PathToPythonModuleOneFile(oneFilObj.Name)
        # TODO: Maybe just take one module ?
        # sys.stdout.write("path=%s mods=%s\n"%(oneFilObj.Name, str(list(lstModules))))
        addedOne = False
        for oneMod in lstModules:
            setPythonModules.add( oneMod )
            addedOne = True
        if not addedOne:
            unknownDataFiles.append( oneFilObj )

    return setPythonModules, unknownDataFiles


################################################################################

# This stores, on Linux, the package from where a file came from.
# So, in Docker, a file used by a process is not copied, but its package installed.
class FileToPackage:
    def __init__(self):
        tmpDir = tempfile.gettempdir()
        # This file stores and reuses the map from file name to Linux package.
        self.m_cacheFileName = tmpDir + "/" + "FileToPackageCache." + socket.gethostname() + ".txt"
        try:
            fdCache = open(self.m_cacheFileName,"r")
        except:
            sys.stdout.write("Cannot open packages cache file:%s.\n" % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = False
            return

        try:
            self.m_cacheFilesToPackages = json.load(fdCache)
            fdCache.close()
            self.m_dirtyCache = False
            sys.stdout.write("Loaded packages cache file:%s\n"%self.m_cacheFileName)
        except:
            sys.stdout.write("Error reading packages cache file:%s. Resetting.\n" % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = True

    # Dump cache to a file. It does not use __del__()
    # because it cannot access some global names in recent versions of Python.
    def DumpToFile(self):
        if self.m_dirtyCache:
            try:
                fdCache = open(self.m_cacheFileName,"w")
                sys.stdout.write("Dumping to packages cache file %s\n"%self.m_cacheFileName)
                json.dump(self.m_cacheFilesToPackages,fdCache)
                fdCache.close()
            except IOError:
                raise Exception("Cannot dump packages cache file to %s"%self.m_cacheFileName)

    @staticmethod
    def OneFileToPackageLinuxNoCache(oneFilNam):
        if sys.platform.startswith("linux"):
            aCmd = ['rpm','-qf',oneFilNam]

            try:
                aPop = subprocess.Popen(aCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                anOut, anErr = aPop.communicate()
                aPack = anOut
                aPack = aPack.strip()
                if aPack.endswith("is not owned by any package"):
                    lstPacks = []
                elif aPack == "":
                    lstPacks = []
                else:
                    lstPacks = aPack.split("\n")
                    if lstPacks[0] == "":
                        raise Exception("Inserting invalid package")
                return lstPacks
            except:
                return []
        else:
            return None

    unpackagedPrefixes = ["/dev/","/home/","/proc/","/tmp/","/sys/","/var/cache/"] + CIM_DataFile.m_nonFilePrefixes

    @staticmethod
    def CannotBePackaged(filNam):
        # Some files cannot be packaged, ever.
        for pfx in FileToPackage.unpackagedPrefixes:
            if filNam.startswith(pfx):
                return True
        return False

    def OneFileToPackageLinux(self,oneFilObj):
        oneFilNam = oneFilObj.Name

        # Very common case of a file which is only local.
        if FileToPackage.CannotBePackaged(oneFilNam):
            return []
        try:
            return self.m_cacheFilesToPackages[oneFilNam]
        except KeyError:
            lstPacks= self.OneFileToPackageLinuxNoCache(oneFilNam)

            if lstPacks:
                self.m_dirtyCache = True

            # TODO: Optimisation: Once we have detected a file of a package,
            # this loads all files from this package because reasonably,
            # there will be other files from it.
            # rpm -qf /usr/lib64/libselinux.so.1
            # rpm -q -l libselinux-2.6-6.fc26.x86_64
            self.m_cacheFilesToPackages[oneFilNam] = lstPacks

            return lstPacks


    def GetPackagesList(self,lstPackagedFiles):

        # This command is very slow:
        # dnf provides /usr/bin/as

        # This is quite fast:
        # rpm -qf /bin/ls

        lstPackages = set()
        unknownFiles = []

        for oneFil in lstPackagedFiles:
            # sys.stdout.write("oneFil=%s tp=%s\n"%(oneFil,str(type(oneFil))))
            lstPacks = self.OneFileToPackageLinux(oneFil)
            if lstPacks:
                # BEWARE: This takes the first pack, randomly.
                aPack = lstPacks[0]
                if aPack == "":
                    raise Exception("Invalid package for file=%s\n"%oneFil)
                lstPackages.add(aPack)
            else:
                unknownFiles.append(oneFil)
        return lstPackages, unknownFiles

# We can keep the same cache for all simulations because
# they were all run on the same machine.
G_FilesToPackagesCache = FileToPackage()

atexit.register( FileToPackage.DumpToFile, G_FilesToPackagesCache )

################################################################################

# Display the dependencies of process.
# They might need the installation of libraries. modules etc...
# Sometimes these dependencies are the same.
# The type of process can be: "Binary", "Python", "Perl" etc...
# and for each of these it receive a list of strings, each of them models
# a dependency: a RPM package, a Python module etc...
# Sometimes, they can be be similar and will therefore be loaded once.
# The type of process contains some specific code which can generate
# the Dockerfile commands for handling these dependencies.
#
def GenerateDockerProcessDependencies(dockerDirectory, fdDockerFile):

    # TODO: Do not duplicate Python modules installation.
    def InstallPipModule(fdDockerFile,namePyModule):
        fdDockerFile.write("RUN pip --disable-pip-version-check install %s\n"%namePyModule)

    def InstallLinuxPackage(fdDockerFile,packageName):

        # packageName = "mariadb-libs-10.1.30-2.fc26.x86_64"
        # RUN yum install mariadb-libs
        if packageName in InstallLinuxPackage.InstalledPackages:
            pckShort = InstallLinuxPackage.InstalledPackages[ packageName ]
            fdDockerFile.write("# Already installed %s -> %s\n" % (pckShort, packageName) )
            return

        # TODO: Maybe there are several versions of the same package.
        mtch = re.search(r'(.*)-(.*)-(.*?)\.(.*)', packageName)
        if mtch:
            ( pckShort, version, release, platform ) = mtch.groups()
        else:
            pckShort = packageName

        InstallLinuxPackage.InstalledPackages[ packageName ] = pckShort

        # Step 4/7 : RUN yum -y install coreutils # coreutils-8.27-5.fc26.x86_64
        # Problem: problem with installed package coreutils-single-8.29-5.fc28.x86_64
        # - package coreutils-8.29-5.fc28.x86_64 conflicts with coreutils-single provided by coreutils-single-8.29-5.fc28.x86_64
        # (try to add '--allowerasing' to command line to replace conflicting packages or '--skip-broken' to skip uninstallable packages)

        # For the moment, this is simpler.
        if pckShort in ['coreutils']:
            fdDockerFile.write("# Potential conflict with %s , %s\n" % (pckShort, packageName) )
        else:
            fdDockerFile.write("RUN yum -y install %s # %s\n" % (pckShort, packageName) )

    # Each package is installed only once.
    InstallLinuxPackage.InstalledPackages = dict()

    # FIXME: We could copy an entire directory tree. When ?
    def AddToDockerDir(pathName,filComment = 0):
        # Maybe the input file does not exist.
        if not os.path.exists(pathName):
            fdDockerFile.write("# Origin file does not exist:%s\n" % (pathName) )
            return

        # No need to copy directories.
        if os.path.isdir(pathName):
            return

        orgDir = os.path.dirname(pathName)
        dstDir = dockerDirectory + "/" + orgDir

        if not os.path.exists(dstDir):
            os.makedirs(dstDir)
        dstPath = dockerDirectory + "/" + pathName
        try:
            # Copy the file at the right place, so "docker build" can find it.
            shutil.copy(pathName, dstPath)
        except IOError:
            sys.stdout.write("Failed copy %s to %s\n"%(pathName,dstPath) )
            # Maybe the file is not there because this is in replay mode,
            # rerunning a session form the log file. This is not a problem.
            fdDockerFile.write("# Cannot add non-existent file:%s\n" % (pathName) )
            return

        if filComment:
            fdDockerFile.write("# %s\n" % (filComment) )

        fdDockerFile.write("ADD %s %s\n" % (pathName,pathName) )

    # Code dependencies and data files dependencies are different.

    # All versions mixed together which is realistic most of times.
    class Dependency:
        def __init__(self):
            self.m_accessedCodeFiles = set()

        def AddDep(self,pathName):
            self.m_accessedCodeFiles.add(pathName)

    class DependencyPython(Dependency,object):
        DependencyName = "Python scripts"

        def __init__(self):
            super( DependencyPython,self).__init__()

        @staticmethod
        def IsDepType(objInstance):
            try:
                # Detection with strace:
                # execve("/usr/bin/python", ["python", "TestProgs/mineit_mys"...], [/* 22 vars */]) = 0
                # Detection with ltrace:
                # __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
                return objInstance.Executable.find("/python") >= 0 or objInstance.Executable.startswith("python")
            except AttributeError:
                # We do not know the executable, or it is a thread.
                return False

        @staticmethod
        def IsCode(objDataFile):
            return objDataFile.Name.endswith(".py") or objDataFile.Name.endswith(".pyc")

        def GenerateDockerDependencies(self,fdDockerFile):
            packagesToInstall = set()

            for objDataFile in self.m_accessedCodeFiles:
                filNam = objDataFile.Name
                if filNam.find("packages") >= 0:
                    # Now this trucates the file name to extract the Python package name.
                    # filNam = '/usr/lib64/python2.7/site-packages/MySQLdb/constants/CLIENT.pyc'
                    splitFil = filNam.split("/")
                    try:
                        ixPack = splitFil.index("site-packages")
                    except ValueError:
                        try:
                            ixPack = splitFil.index("dist-packages")
                        except ValueError:
                            ixPack = -1
                            pass

                    if (ixPack >= 0) and (ixPack < len(splitFil)-1):
                        pckNam = splitFil[ixPack+1]
                        if not pckNam.endswith(".py") and not pckNam.endswith(".pyc"):
                            # filNam = 'abrt_exception_handler.py'
                            packagesToInstall.add( splitFil[ixPack+1] )
                elif filNam.startswith("/usr/lib/python2.7/"):
                    # Then a source file coming with Python: "/usr/lib/python2.7/string.py"
                    pass
                else:
                    # Must avoid copying file from the standard installation and always available, such as:
                    # "ADD /usr/lib64/python2.7/cgitb.py /"
                    # TODO: Use the right path:
                    if not filNam.startswith("/usr/lib64/python2.7"):
                        # ADD /home/rchateau/rdfmon-code/Experimental/RetroBatch/TestProgs/big_mysql_select.py /
                        AddToDockerDir(filNam)

            if packagesToInstall or self.m_accessedCodeFiles:
                InstallLinuxPackage( fdDockerFile, "python")
            for onePckgNam in sorted(packagesToInstall):
                # TODO: Do not duplicate Python modules installation.
                InstallPipModule(fdDockerFile,onePckgNam)

    class DependencyPerl(Dependency,object):
        DependencyName = "Perl scripts"

        def __init__(self):
            super( DependencyPerl,self).__init__()

        @staticmethod
        def IsDepType(objInstance):
            try:
                return  objInstance.Executable.find("/perl") >= 0
            except AttributeError:
                # We do not know the executable, or it is a thread.
                return False

        @staticmethod
        def IsCode(objDataFile):
            return objDataFile.Name.endswith(".pl")

        def GenerateDockerDependencies(self,fdDockerFile):
            for objDataFile in self.m_accessedCodeFiles:
                filNam = objDataFile.Name
                fdDockerFile.write("RUN cpanm %s\n"%filNam)
            pass

    class DependencyBinary(Dependency,object):
        DependencyName = "Binary programs"

        def __init__(self):
            super( DependencyBinary,self).__init__()

        @staticmethod
        def IsDepType(objInstance):
            # Always true because tested at the end as a default.
            # The executable should at least be an executable file.
            return True

        @staticmethod
        def IsCode(objDataFile):
            return objDataFile.Name.find(".so") > 0

        @staticmethod
        # This detects the libraries which are always in the path.
        #
        def IsSystemLib(filNam):
            basNam = os.path.basename(filNam)
            if basNam in ["ld.so.cache","ld.so.preload"]:
                return True

            # Eliminates the extension and the version.
            noExt = basNam[ : basNam.find(".") ]
            noExt = noExt[ : noExt.find("-") ]
            if noExt in ["libdl","libc","libacl","libm","libutil","libpthread"]:
                return True
            return False
            
        def GenerateDockerDependencies(self,fdDockerFile):
            # __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
            #    return objInstance.Executable.find("/python") >= 0 or objInstance.Executable.startswith("python")

            lstAccessedPackages, unpackagedAccessedCodeFiles = G_FilesToPackagesCache.GetPackagesList(self.m_accessedCodeFiles)

            fdDockerFile.write("# Package installations:\n")
            for namPackage in sorted(lstAccessedPackages):
                InstallLinuxPackage( fdDockerFile, namPackage )
            fdDockerFile.write("\n")

            fdDockerFile.write("# Non-packaged executable files copies:\n")
            sortAccessedCodeFiles = sorted( unpackagedAccessedCodeFiles, key=lambda x: x.Name )
            for objDataFile in sortAccessedCodeFiles:
                filNam = objDataFile.Name
                AddToDockerDir(filNam)


    lstDependencies = [
        DependencyPython(),
        DependencyPerl(),
        DependencyBinary(),
    ]

    accessedDataFiles = set()

    # This is the complete list of extra executables which have to be installed.
    lstBinaryExecutables = set()

    # This is a subset of lstDependencies.
    setUsefulDependencies = set()

    for objPath,objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
        for oneDep in lstDependencies:
            # Based on the executable of the process,
            # this tells if we might have dependencies of this type: Python Perl etc...
            if oneDep.IsDepType(objInstance):
                setUsefulDependencies.add(oneDep)
                break

        for filAcc in objInstance.m_ProcessFileAccesses:
            oneFile = filAcc.m_objectCIM_DataFile
            if oneDep and oneDep.IsCode(oneFile):
                oneDep.AddDep(oneFile)
            else:
                accessedDataFiles.add(oneFile)
        
        try:
            anExec = objInstance.m_ExecutableObject
            # sys.stdout.write("Add exec=%s tp=%s\n" % (anExec,str(type(anExec))))
            lstBinaryExecutables.add(anExec)
        except AttributeError:
            pass

    # Install or copy the executables.
    # Beware that some of them are specifically installed: Python, Perl.
    fdDockerFile.write("################################# Executables:\n")
    lstPackages, unknownBinaries = G_FilesToPackagesCache.GetPackagesList(lstBinaryExecutables)
    for anExec in sorted(lstPackages):
        InstallLinuxPackage( fdDockerFile, anExec )
    fdDockerFile.write("\n")

    # This must be done after the binaries are installed: For example installing Perl packages
    # with CPAN needs to install Perl.
    fdDockerFile.write("################################# Dependencies by program type\n")
    for oneDep in setUsefulDependencies:
        fdDockerFile.write("# Dependencies: %s\n"%oneDep.DependencyName)
        oneDep.GenerateDockerDependencies(fdDockerFile)
        fdDockerFile.write("\n")

    # These are not data files.
    categoriesNotInclude = set([
        "Temporary files",
        "Pipes and terminals",
        "Kernel file systems",
        "System config files",
        "Connected TCP sockets",
        "Other TCP/IP sockets",
    ])

    lstPackagesData, unpackagedDataFiles = G_FilesToPackagesCache.GetPackagesList(accessedDataFiles)

    setPythonModules, unknownDataFiles = FilesToPythonModules(unpackagedDataFiles)

    if setPythonModules:
        fdDockerFile.write("# Python modules:\n")
        for onePyModu in sorted(setPythonModules):
            InstallPipModule(fdDockerFile,onePyModu)
        fdDockerFile.write("\n")

    fdDockerFile.write("# Data packages:\n")
    # TODO: Many of them are probably already installed.
    for anExec in sorted(lstPackagesData):
        InstallLinuxPackage( fdDockerFile, anExec )
    fdDockerFile.write("\n")

    if unknownDataFiles:
        fdDockerFile.write("# Data files:\n")
        # Sorted by alphabetical order.
        # It would be better to sort it after filtering.
        sortedDatFils = sorted(unknownDataFiles, key=lambda x: x.Name )
        for datFil in sortedDatFils:
            # DO NOT ADD DIRECTORIES.
    
            if datFil.Category in categoriesNotInclude:
                continue
            
            filNam = datFil.Name
            if filNam.startswith("/usr/include/"):
                continue
            if filNam.startswith("/usr/bin/"):
                continue
            if filNam.startswith("UnknownFileDescr:"):
                continue
            if filNam in ["-1","stdin","stdout","stderr","."]:
                continue

            # Primitive tests so that directories are not copied.
            if filNam.endswith("/.") or filNam.endswith("/"):
                continue

            AddToDockerDir(filNam,datFil.Category)
    fdDockerFile.write("\n")
    

def GenerateDockerFile(dockerFilename):
    fdDockerFile = open(dockerFilename, "w")

    # This write in the DockerFile, the environment variables accessed
    # by processes. For the moment, all env vars are mixed together,
    # which is inexact, strictly speaking.
    def WriteEnvironVar():
        for envNam in G_EnvironmentVariables:
            envVal = G_EnvironmentVariables[envNam]
            if envVal == "":
                # Error response from daemon: ENV must have two arguments
                envVal = '""'
            fdDockerFile.write("ENV %s %s\n" % (envNam, envVal ) )
            
        fdDockerFile.write("\n")
        
    def WriteProcessTree():
        """Only for documentation purpose"""
        def WriteOneProcessSubTree(objProc,depth):
            commandLine = objProc.GetCommandLine()
            if not commandLine:
                commandLine = "????"
            fdDockerFile.write("# %s -> %s : %s %s\n" % ( TimeStampToStr(objProc.CreationDate), TimeStampToStr(objProc.TerminationDate), "    "*depth , commandLine ) )
            
            for subProc in sorted( objProc.m_subProcesses, key=lambda x: x.Handle ):
                WriteOneProcessSubTree(subProc,depth+1)

        fdDockerFile.write("# Processes tree\n" )

        procsTopLevel = CIM_Process.GetTopProcesses()
        for oneProc in sorted(procsTopLevel, key=lambda x: x.Handle):
            WriteOneProcessSubTree( oneProc, 1 )
        fdDockerFile.write("\n" )

    currNow = datetime.datetime.now()
    currDatTim = currNow.strftime("%Y-%m-%d %H:%M:%S:%f")
    fdDockerFile.write("# Dockerfile generated %s\n"%currDatTim)
    
    dockerDirectory = os.path.dirname(dockerFilename)
    fdDockerFile.write("# Directory %s\n"%dockerDirectory)
    fdDockerFile.write("\n")

    fdDockerFile.write("FROM docker.io/fedora\n")
    fdDockerFile.write("\n")

    fdDockerFile.write("MAINTAINER contact@primhillcomputers.com\n")
    fdDockerFile.write("\n")

    GenerateDockerProcessDependencies(dockerDirectory, fdDockerFile)

    # Top-level processes, which starts the other ones.
    # Probably there should be one only, but this is not a constraint.
    procsTopLevel = CIM_Process.GetTopProcesses()
    for oneProc in procsTopLevel:
        # TODO: Possibly add the command "VOLUME" ?
        currDir = oneProc.GetProcessCurrentDir()
        fdDockerFile.write("WORKDIR %s\n"%currDir)

        commandList = oneProc.GetCommandList()
        if commandList:
            # If the string length read by ltrace or strace is too short,
            # some arguments are truncated: 'CMD ["python TestProgs/big_mysql_..."]'

            # There should be one CMD command only !
            strCmd = ",".join( '"%s"' % wrd for wrd in commandList )

            fdDockerFile.write("CMD [ %s ]\n" % strCmd )
    fdDockerFile.write("\n")

    portsList = CIM_DataFile.GetExposedPorts()
    if portsList:
        fdDockerFile.write("# Port numbers:\n")
        for onePort in portsList:
            try:
                txtPort = socket.getservbyport(int(onePort))
                fdDockerFile.write("# Service: %s\n"%txtPort)
            except:
                fdDockerFile.write("# Unknown service number: %s\n"%onePort)
            fdDockerFile.write("EXPOSE %s\n"%onePort)
        fdDockerFile.write("\n")

    WriteEnvironVar()
    
    WriteProcessTree()

    # More examples here:
    # https://github.com/kstaken/dockerfile-examples/blob/master/couchdb/Dockerfile
    
    fdDockerFile.close()
    return


################################################################################

# This associates file descriptors to path names when strace and the option "-y"
# cannot be used. There are predefined values.
G_mapFilDesToPathName = None

# strace associates file descriptors to the original file or socket which created it.
# Option "-y          Print paths associated with file descriptor arguments."
# read ['3</usr/lib64/libc-2.21.so>']
# This returns a WMI object path, which is self-descriptive.
# FIXME: Are file descriptors shared between processes ?
def STraceStreamToPathname(strmStr):
    idxLT = strmStr.find("<")
    if idxLT >= 0:
        pathName = strmStr[ idxLT + 1 : -1 ]
    else:
        # If the option "-y" is not available, with ltrace or truss.
        # Theoretically the path name should be in the map.
        try:
            pathName = G_mapFilDesToPathName[ strmStr ]
        except KeyError:
            if strmStr == "-1": # Normal return value.
                pathName = "Invalid device"
            else:
                pathName = "UnknownFileDescr:%s" % strmStr

    return pathName

################################################################################

# ltrace logs
# [pid 6414] 23:58:46.424055 __libc_start_main([ "gcc", "TestProgs/HelloWorld.c" ] <unfinished ...>
# [pid 6415] 23:58:47.905826 __libc_start_main([ "/usr/libexec/gcc/x86_64-redhat-linux/5.3.1/cc1", "-quiet", "TestProgs/HelloWorld.c", "-quiet"... ] <unfinished ...>


# Typical strings displayed by strace:
# [pid  7492] 07:54:54.205073 wait4(18381, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18381 <0.000894>
# [pid  7492] 07:54:54.206000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18381, si_uid=1000, si_status=1, si_utime=0, si_stime=0 } ---
# [pid  7492] 07:54:54.206031 newfstatat(7</home/rchateau/rdfmon-code/primhill>, "Survol", {st_mode=S_IFDIR|0775, st_size=4096, ...}, AT_SYMLIN K_NOFOLLOW) = 0 <0.000012>
# [pid  7492] 07:54:54.206113 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fb0d303fad0) = 18382 <0.000065>
# [pid  7492] 07:54:54.206217 wait4(18382, grep: ../../primhill/Survol: Is a directory
# [pid  7492] [{WIFEXITED(s) && WEXITSTATUS(s) == 2}], 0, NULL) = 18382 <0.000904>
# 07:54:54.207500 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18382, si_uid=1000, si_status=2, si_utime=0, si_stime=0 } ---

class BatchStatus:
    unknown    = 0
    plain      = 1
    unfinished = 2
    resumed    = 3
    matched    = 4 # After the unfinished has found its resumed half.
    merged     = 5 # After the resumed has found its unfinished half.
    sequence   = 6
    chrDisplayCodes = "? URmM "


class BatchLetCore:
    # The input line is read from "strace" command.
    # [pid  7639] 09:35:56.198010 wait4(7777,  <unfinished ...>
    # 09:35:56.202030 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 7777 <0.004010>
    # [pid  7639] 09:35:56.202303 wait4(7778,  <unfinished ...>
    #
    # It works with ltrace, in a certain extent.
    # [pid 3916] 13:20:17.215298 open@SYS("/usr/lib64/python2.7/site-packages/_mysql.so", 0, 0666)                      = 4 <0.000249>
    # [pid 3916] 13:20:17.215576 fstat@SYS(4, 0x7ffd2f04fd50)                                                           = 0 <0.000038>
    # [pid 3916] 13:20:17.215671 open@SYS("/usr/lib64/python2.7/site-packages/_mysql.so", 0x80000, 01674553140)         = 5 <0.000256>
    # [pid 3916] 13:20:17.216004 read@SYS(5, "\177ELF\002\001\001", 832)                                                = 832 <0.000042>

    def __init__(self):
        self.m_retValue = "N/A"
        self.m_status = BatchStatus.unknown

        # Both cannot be set at the same time.
        self.m_unfinishedBatch = None # If this is an merged batch.
        self.m_resumedBatch = None # If this is an matched batch.

        # sys.stdout.write("self=%d\n" % id(self) )
        return

    # tracer = "strace|ltrace"
    def ParseLine( self, oneLine, tracer ):
        # sys.stdout.write("%s oneLine1=%s" % (id(self),oneLine ) )
        self.m_tracer = tracer

        if oneLine.startswith( "[pid" ):
            idxAfterPid = oneLine.find("]")

            pidParsed = int( oneLine[ 4:idxAfterPid ] )

            # This is a sub-process.
            self.m_pid = pidParsed

            self.InitAfterPid(oneLine, idxAfterPid + 2 )
        else:
            # This is the main process, but at this stage we do not have its pid.
            self.m_pid = G_topProcessId
            self.InitAfterPid(oneLine, 0)

        # If this process is just created, it receives the creation time-stamp.
        self.m_objectProcess = ToObjectPath_CIM_Process(self.m_pid)

        # If the creation date is uknown, it is at least equal to the current call time.
        if not self.m_objectProcess.CreationDate:
            self.m_objectProcess.CreationDate = self.m_timeStart

    def SetFunction(self, funcFull):
        # With ltrace, systems calls are suffix with the string "@SYS".
        if self.m_tracer == "strace":
            # strace can only intercept system calls.
            assert not funcFull.endswith("@SYS")
            self.m_funcNam = funcFull + "@SYS"
        elif self.m_tracer == "ltrace":

            # This might be in a shared library, so this extracts the function name:
            # libaugeas.so.0->getenv
            # libaugeas.so.0->getenv
            # libclntsh.so.11.1->getenv
            # libclntsh.so.11.1->getenv
            # libpython2.7.so.1.0->getenv
            funcFull = funcFull.split("->")[-1]

            # ltrace does not add "@SYS" when the function is resumed:
            #[pid 18316] 09:00:22.600426 rt_sigprocmask@SYS(0, 0x7ffea10cd370, 0x7ffea10cd3f0, 8 <unfinished ...>
            #[pid 18316] 09:00:22.600494 <... rt_sigprocmask resumed> ) = 0 <0.000068>
            if self.m_status == BatchStatus.resumed:
                self.m_funcNam = funcFull + "@SYS"
            else:
                # On RHEL4, the function is prefixed by "SYS_"
                if funcFull.startswith("SYS_"):
                    assert not funcFull.endswith("@SYS")
                    self.m_funcNam = funcFull[4:] + "@SYS"
                else:
                    assert funcFull.endswith("@SYS")
                    self.m_funcNam = funcFull

            # It does not work with this:
            #[pid 4784] 16:42:10.781324 Py_Main(2, 0x7ffed52a8038, 0x7ffed52a8050, 0 <unfinished ...>
            #[pid 4784] 16:42:12.166187 <... Py_Main resumed> ) = 0 <1.384547>
            #
            # The only thing we can do is register the function names which have been seen as unfinished,
            # store their prefix and use this to correctly suffix them or not.

        else:
            raise Exception("SetFunction tracer %s unsupported"%self.m_trace)

    def SetDefaultOnError(self):
        self.SetFunction( "" )
        self.m_parsedArgs = []
        self.m_retValue = None

    # This parsing is specific to strace and ltrace.
    def InitAfterPid(self,oneLine, idxStart):
        # "07:54:54.206113"
        aTimeStamp = oneLine[idxStart:idxStart+15]

        self.m_timeStart = aTimeStamp
        self.m_timeEnd = aTimeStamp
        theCall = oneLine[idxStart+16:]

        # "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19332, si_uid=1000, si_status=1, si_utime=0, si_stime=0} ---"
        if theCall.startswith( "--- " ):
            raise ExceptionIsExit()

        # "+++ exited with 1 +++ ['+++ exited with 1 +++']"
        if theCall.startswith( "+++ " ):
            raise ExceptionIsSignal()


        # Specific logic of interrupted calls.
        # [pid 12666] 14:50:45.609523 wait4@SYS(-1, 0x7ffd59a919e0, 0, 0 <unfinished ...>
        # [pid 12666] 14:50:45.666995 <... wait4 resumed> ) = 0x317b <0.057470>

        # ... with functions which do not implying signals or processes:
        # [pid 12693] 14:55:38.882089 fwrite(" ?", 2, 1, 0x7f93548c5620 <unfinished ...>
        # [pid 12693] 14:55:38.882412 <... fwrite resumed> ) = 1 <0.000319>

        # Sometimes on two recursive levels:
        # [pid 12753] 14:56:54.288041 sigaction(SIGCHLD, { nil, <>, 0, nil } <unfinished ...>
        # [pid 12753] 14:56:54.288231 rt_sigaction@SYS(17, 0x7ffe7c383380, 0x7ffe7c383420, 8 <unfinished ...>
        # [pid 12753] 14:56:54.288299 <... rt_sigaction resumed> ) = 0 <0.000069>
        # [pid 12753] 14:56:54.288404 <... sigaction resumed> , { 0x5612836832c0, <>, 0, nil }) = 0 <0.000361>

        # "[pid 18534] 19:58:38.406747 wait4(18666,  <unfinished ...>"
        # "19:58:38.410766 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18666 <0.004009>"

        idxGT = theCall.rfind(">")
        # sys.stdout.write("idxGT=%d\n" % idxGT )
        idxLT = theCall.rfind("<",0,idxGT)
        # sys.stdout.write("idxLT=%d\n" % idxLT )
        self.m_status = BatchStatus.plain
        if idxLT >= 0 :
            exeTm = theCall[idxLT+1:idxGT]
            if exeTm == "unfinished ...":
                self.m_execTim = ""
                self.m_status = BatchStatus.unfinished
            else:
                self.m_execTim = theCall[idxLT+1:idxGT]
        else:
            self.m_execTim = ""

        # Another scenario:
        # [pid 11761] 10:56:39.125823 close@SYS(4 <unfinished ...>
        # [pid 11762] 10:56:39.125896 mmap@SYS(nil, 4096, 3, 34, -1, 0 <unfinished ...>
        # [pid 11761] 10:56:39.125939 <... close resumed> ) = 0 <0.000116>
        # [pid 11762] 10:56:39.125955 <... mmap resumed> ) = 0x7f75198d5000 <0.000063>
        matchResume = re.match(r"<\.\.\. ([^ ]*) resumed> (.*)", theCall)
        if matchResume:
            self.m_status = BatchStatus.resumed
            # TODO: Should check if this is the correct function name.
            funcNameResumed = matchResume.group(1)
            self.SetFunction( funcNameResumed )

            # ") = 0 <0.000069>"
            # ", { 0x5612836832c0, <>, 0, nil }) = 0 <0.000361>"

            # Offset of the second match.
            # A 'resumed' function call does not have an opening parenthesis.
            idxPar = matchResume.start(2) - 1

        else:
            idxPar = theCall.find("(")

            if idxPar <= 0 :
                # With ltrace only, wrong detection: https://github.com/dkogan/ltrace/blob/master/TODO
                # oneLine='error: maximum array length seems negative, "\236\245\v", 8192) = -21'
                if (self.m_tracer == "ltrace"):
                    if oneLine.startswith("error:"):
                        sys.stdout.write("Warning ltrace:%s\n"%oneLine)
                        self.SetDefaultOnError()
                        return

                # Exception: No function in:22:50:11.879132 <... exit resumed>) = ?
                # Special case, when it is leaving:
                elif (self.m_tracer == "strace"):
                    if ( oneLine.find("<... exit resumed>) = ?") >= 0 ):
                        sys.stdout.write("Warning strace exit:%s"%oneLine)
                        self.SetDefaultOnError()
                        return

                    if ( oneLine.find("<... exit_group resumed>) = ?") >= 0 ):
                        sys.stdout.write("Warning strace exit_group:%s\n"%oneLine)
                        self.SetDefaultOnError()
                        return

                raise Exception("No function in:%s"%oneLine)

            self.SetFunction( theCall[:idxPar] )

        self.m_parsedArgs, idxLastPar = ParseCallArguments(theCall,idxPar+1)

        if self.m_status == BatchStatus.unfinished:
            # 18:46:10.920748 execve("/usr/bin/ps", ["ps", "-ef"], [/* 33 vars */] <unfinished ...>
            self.m_retValue = None
        else:
            # The parameters list might be broken, with strings containing an embedded double-quote.
            if idxLastPar < 0:
                # The parameters list might be broken, with strings containing an embedded double-quote.
                # So the closing parenthesis could not be found.
                idxEq = theCall.rfind( "=", 0, idxLT )
                if idxEq < 0:
                    raise Exception("No = from end: idxLT=%d. theCall=%s"%(idxLT,theCall))
            else:
                # Normal case where the '=' equal sign comes after the clolsing parenthese of the args list.
                idxEq = theCall.find( "=", idxLastPar )
                if idxEq < 0:
                    # This is acceptable in this circumstance only.
                    if not theCall.endswith("<no return ...>\n") and not theCall.endswith("<detached ...>"):
                        if self.m_tracer != "ltrace":
                        # This can happen with ltrace which does not escape double-quotes. Example:
                        # read@SYS(8, "\003\363\r\n"|\314Vc", 4096) = 765 <0.000049>
                            raise Exception("No = from parenthesis: idxLastPar=%d. theCall=%s. Len=%d"%(idxLT,theCall,len(theCall)))

            self.m_retValue = theCall[ idxEq + 1 : idxLT ].strip()
            # sys.stdout.write("idxEq=%d idxLastPar=%d idxLT=%d retValue=%s\n"%(idxEq,idxLastPar,idxLT,self.m_retValue))

    def AsStr(self):
        return "%s %s s=%s" % (
            str(self.m_parsedArgs),
            self.m_retValue,
            BatchStatus.chrDisplayCodes[ self.m_status ] )

def CreateBatchCore(oneLine,tracer):

    try:
        batchCore = BatchLetCore()
        batchCore.ParseLine( oneLine, tracer )
        return batchCore
    except ExceptionIsExit:
        return None
    except ExceptionIsSignal:
        return None

################################################################################

# These system calls are not taken into account because they do not give
# any dependency between the process and other resources,
# so we are not interested by their return value.
G_ignoredSyscalls = [
    "arch_prctl",
    "brk",
    "futex",
    "clock_getres",
    "clock_gettime",
    "getegid",
    "geteuid",
    "getgid",
    "getpgid",
    "getpid",
    "getpgrp",
    "getppid",
    "getresgid",
    "getrlimit",
    "gettid",
    "getuid",
    "lseek",
    "mlock",
    "mprotect",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "set_robust_list",
    "set_tid_address",
    "setpgid",
    "setpgrp",
    "times",
]


# Each class is indexed with the name of the corresponding system call name.
# If the class is None, it means that this function is explicitly neglected.
# If it is not defined after metaclass registration, then it is processed by BatchLetBase.
# Derived classes of BatchLetBase self-register thanks to the metaclass.
# At init time, this map contains the systems calls which should be ignored.

G_batchModels = { sysCll + "@SYS" : None for sysCll in G_ignoredSyscalls }

# This metaclass allows derived class of BatchLetBase to self-register their function name.
# So, the name of a system call is used to lookup the class which represents it.
class BatchMeta(type):
    # This registers function names using the name of the derived class which is properly truncated.
    # TODO: It would be cleaner to add members in the class cls, instead of using the class name
    # to characterize the function.
    def __init__(cls, name, bases, dct):
        global G_batchModels

        # This is for Linux system calls.
        btchSysPrefix = "BatchLetSys_"

        # This is for plain libraries functions: "__libc_start_main", "Py_Main" and
        # functions like "libpython2.7.so.1.0->getenv", "libperl.so.5.24->getenv" etc...
        btchLibPrefix = "BatchLetLib_"

        if name.startswith(btchSysPrefix):
            syscallName = name[len(btchSysPrefix):] + "@SYS"
            # sys.stdout.write("Registering sys function:%s\n"%syscallName)
            G_batchModels[ syscallName ] = cls
        elif name.startswith(btchLibPrefix):
            syscallName = name[len(btchLibPrefix):]
            # sys.stdout.write("Registering lib function:%s\n"%syscallName)
            G_batchModels[ syscallName ] = cls
        elif name not in ["NewBase","BatchLetBase","BatchLetSequence"]:
            # Enumerate the list of legal base classes, for safety only.
            raise Exception("Invalid class name:%s"%name)

        super(BatchMeta, cls).__init__(name, bases, dct)

# This is portable on Python 2 and Python 3.
# No need to import the modules six or future.utils
def my_with_metaclass(meta, *bases):
    return meta("NewBase", bases, {})

# All class modeling a system call inherit from this.
class BatchLetBase(my_with_metaclass(BatchMeta) ):

    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self,batchCore,style="Orig"):
        self.m_core = batchCore
        self.m_occurrences = 1
        self.m_style = style

        # Maybe we could get rid of the parsed args as they are not needed anymore.
        self.m_significantArgs = self.m_core.m_parsedArgs

    def __str__(self):
        return self.m_core.m_funcNam

    def SignificantArgs(self):
        return self.m_significantArgs

    # This is used to detect repetitions.
    def GetSignature(self):
        return self.m_core.m_funcNam

    def GetSignatureWithArgs(self):
        try:
            # This is costly so we calculate it once only.
            return self.m_signatureWithArgs
        except AttributeError:
            self.m_signatureWithArgs = self.m_core.m_funcNam + ":" + "&".join( map( str, self.m_significantArgs ) )
            return self.m_signatureWithArgs

    # This is very often used.
    def StreamName(self,idx=0):
        aFil = self.STraceStreamToFile( self.m_core.m_parsedArgs[idx] )
        return [ aFil ]

    def SameCall(self,anotherBatch):
        if self.m_core.m_funcNam != anotherBatch.m_core.m_funcNam:
            return False

        return self.SameArguments(anotherBatch)

    # This assumes that the function calls are the same.
    # It compares the arguments one by one.
    def SameArguments(self,anotherBatch):
        args1 = self.SignificantArgs()
        args2 = anotherBatch.SignificantArgs()

        # sys.stdout.write("%s args1=%s\n" % ( self.m_core.m_funcNam, str(args1)) )
        # sys.stdout.write("%s args2=%s\n" % ( anotherBatch.m_core.m_funcNam, str(args2)) )

        # At least they should have the same number of arguments.
        if len(args1) != len(args2):
            return False

        idx = 0
        for val1 in args1:
            val2 = args2[idx]

            if val1 != val2:
                return False
            idx += 1

        return True

    # Returns the file associated to this path, and creates it if needed.
    # It also associates this file to the process.
    def ToObjectPath_Accessed_CIM_DataFile(self,pathName):
        return ToObjectPath_CIM_DataFile(pathName,self.m_core.m_pid)

    def STraceStreamToFile(self,strmStr):
        return ToObjectPath_CIM_DataFile( STraceStreamToPathname(strmStr), self.m_core.m_pid )



################################################################################

# Formatting function specific to TXT mode output file.
def FmtTim(aTim):
    return aTim

class BatchDumperBase:
    def DocumentStart(self):
        return

    def DocumentEnd(self):
        return

    def Header(self, extra_header):
        return

    def Footer(self):
        return

class BatchDumperTXT(BatchDumperBase):
    def __init__(self,strm):
        self.m_strm = strm

    def DumpBatch(self,batchLet):
        self.m_strm.write("Pid=%6d {%4d/%s}%1s'%-20s' %s ==>> %s (%s,%s)\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            BatchStatus.chrDisplayCodes[ batchLet.m_core.m_status ],
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgs(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperCSV(BatchDumperBase):
    def __init__(self,strm):
        self.m_strm = strm

    def Header(self, extra_header):
        if extra_header:
            self.m_strm.write("%s\n" % extra_header)
        self.m_strm.write("Pid,Occurrences,Style,Function,Arguments,Return,Start,End\n")

    def DumpBatch(self,batchLet):
        self.m_strm.write("%d,%d,%s,%s,%s,%s,%s,%s,%s\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgs(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

# TODO: Must use json package.
class BatchDumperJSON(BatchDumperBase):
    def __init__(self,strm):
        self.m_strm = strm

    def DocumentStart(self):
        self.m_strm.write( '[\n' )
        self.m_top_delimiter = ""

    def DocumentEnd(self):
        self.m_strm.write( ']\n' )

    def Header(self, extra_header):
        self.m_strm.write( self.m_top_delimiter + '[\n' )
        self.m_delimiter = ""
        self.m_top_delimiter = ","

    def DumpBatch(self,batchLet):
        self.m_strm.write(
            self.m_delimiter + '{\n'
            '   "pid" : %d,\n'
            '   "occurrences" : %d,\n'
            '   "style" : "%s",\n'
            '   "status" : %d,\n'
            '   "function" : "%s",\n'
            '   "arguments" : %s,\n'
            '   "return_value" : %s,\n'
            '   "time_start" : "%s",\n'
            '   "time_end" : "%s"\n'
            '}\n' %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            batchLet.m_core.m_funcNam,
            json.dumps( [ str(arg) for arg in batchLet.SignificantArgs()]),
            json.dumps( batchLet.m_core.m_retValue ), # It may contain double-quotes
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )
        self.m_delimiter = ","

    def Footer(self):
        self.m_strm.write( ']\n' )

################################################################################

# Some Linux functions return a file descriptor which can be invalid:
# This is not shown the same way depending on the tracer: strace or ltrace.
# On Linux, ENOENT = 2.
def InvalidReturnedFileDescriptor(fileDes,tracer):
    if tracer == "strace":
        # 09:18:26.452764 open("/usr/lib/python2.7/numbersmodule.so", O_RDONLY|O_LARGEFILE) = -1 ENOENT (No such file or directory) <0.000012>
        if fileDes.find("ENOENT") >= 0 :
            return True
    elif tracer == "ltrace":
        # [pid 4784] 16:42:12.033450 open@SYS("/usr/lib64/python2.7/numbersmodule.so", 0, 0666) = -2 <0.000195>
        if fileDes.find("-2") >= 0 :
            return True
    else:
        raise Exception("Tracer %s not supported yet"%tracer)
    return False

################################################################################

# os.path.abspath removes things like . and .. from the path
# giving a full path from the root of the directory tree to the named file (or symlink)
def ToAbsPath( dirPath, filNam ):
    # This does not apply to pseudo-files such as: "pipe:", "TCPv6:" etc...
    if re.match("^[0-9a-zA-Z_]+:",filNam):
        return filNam

    if filNam in ["stdout","stdin","stderr"]:
        return filNam

    join_path = os.path.join( dirPath, filNam )
    norm_path = os.path.realpath(join_path)
    return norm_path

################################################################################

##### File descriptor system calls.

# Must be a new-style class.
class BatchLetSys_open(BatchLetBase,object):
    def __init__(self,batchCore):
        global G_mapFilDesToPathName

        # TODO: If the open is not successful, maybe it should be rejected.
        if InvalidReturnedFileDescriptor(batchCore.m_retValue,batchCore.m_tracer):
            return
        super( BatchLetSys_open,self).__init__(batchCore)

        if batchCore.m_tracer == "strace":
            # strace has the "-y" option which writes the complete path each time,
            # the file descriptor is used as an input argument.

            # If the open succeeds, the file actually opened might be different,
            # than the input argument. Example:
            # open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libc-2.25.so>
            # Therefore the returned file should be SignificantArgs(),
            # not the input file.
            filObj = self.STraceStreamToFile( self.m_core.m_retValue )
        elif batchCore.m_tracer == "ltrace":
            # The option "-y" which writes the complete path after the file descriptor,
            # is not available for ltrace.
            # Therefore this mapping must be done here, by reading the result of open()
            # and other system calls which create a file descriptor.

            # This logic also should work with strace if the option "-y" is not there.
            pathName = self.m_core.m_parsedArgs[0]
            filDes = self.m_core.m_retValue

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[ filDes ] = pathName
            filObj = self.ToObjectPath_Accessed_CIM_DataFile( pathName )
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

        self.m_significantArgs = [ filObj ]
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(filObj)
        aFilAcc.SetOpenTime(self.m_core.m_timeStart)

# The important file descriptor is the returned value.
# openat(AT_FDCWD, "../list_machines_in_domain.py", O_RDONLY|O_NOCTTY) = 3</home/rchateau/survol/Experimental/list_machines_in_domain.py> <0.000019>
class BatchLetSys_openat(BatchLetBase,object):
    def __init__(self,batchCore):
        global G_mapFilDesToPathName

        super( BatchLetSys_openat,self).__init__(batchCore)

        # Same logic as for open().
        if batchCore.m_tracer == "strace":
            filObj = self.STraceStreamToFile( self.m_core.m_retValue )
        elif batchCore.m_tracer == "ltrace":
            dirNam = self.m_core.m_parsedArgs[0]
        
            if dirNam == "AT_FDCWD":
                # A relative pathname is interpreted relative to the directory
                # referred to by the file descriptor passed as first parameter.
                dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
            else:
                dirPath = self.STraceStreamToFile( dirNam )
        
            filNam = self.m_core.m_parsedArgs[1]

            pathName = ToAbsPath( dirPath, filNam )

            filDes = self.m_core.m_retValue

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[ filDes ] = pathName
            filObj = self.ToObjectPath_Accessed_CIM_DataFile( pathName )
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

        self.m_significantArgs = [ filObj ]
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(filObj)
        aFilAcc.SetOpenTime(self.m_core.m_timeStart)

class BatchLetSys_close(BatchLetBase,object):
    def __init__(self,batchCore):
        # Maybe no need to record it if close is unsuccessful.
        # [pid 10624] 14:09:55.350002 close(2902) = -1 EBADF (Bad file descriptor) <0.000006>
        if batchCore.m_retValue.find("EBADF") >= 0:
            return

        super( BatchLetSys_close,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])
        aFilAcc.SetCloseTime(self.m_core.m_timeEnd)

class BatchLetSys_read(BatchLetBase,object):
    def __init__(self,batchCore):
        try:
            bytesRead = int(batchCore.m_retValue)
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'read@SYS(31'
            # Or: "read(31</tmp>, 0x7ffdd2592930, 8192) = -1 EISDIR (Is a directory)"
            if batchCore.m_retValue.find("EISDIR") >= 0:
                return
            # Or: "read(9<pipe:[15588394]>, 0x7f77a332a7c0, 1024) = -1 EAGAIN"
            if batchCore.m_retValue.find("EAGAIN") >= 0:
                return

            # Or: "read(0</dev/pts/2>,  <detached ...>"
            # TODO: Should be processed specifically.
            # This happens if the buffer contains a double-quote. Example:
            # Error parsing retValue=read@SYS(8, "\003\363\r\n"|\314Vc", 4096)                                                  = 765
            sys.stdout.write("Error parsing retValue=%s\n" % ( batchCore.m_retValue) )
            return

        super( BatchLetSys_read,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])

        aFilAcc.SetRead(bytesRead,self.m_core.m_parsedArgs[1])

# The process id is the return value but does not have the same format
# with ltrace (hexadecimal) and strace (decimal).
# Example: pread@SYS(256, 0x255a200, 0x4000, 0) = 0x4000
def ConvertBatchCoreRetValue(batchCore):
    if batchCore.m_tracer == "ltrace":
        return int(batchCore.m_retValue,16)
    elif batchCore.m_tracer == "strace":
        return int(batchCore.m_retValue)
    else:
        raise Exception("Invalid tracer")

# Pread() is like read() but reads from the specified position in the file without modifying the file pointer.
class BatchLetSys_preadx(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_preadx,self).__init__(batchCore)

        bytesRead = ConvertBatchCoreRetValue(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])
        aFilAcc.SetRead(bytesRead)

class BatchLetSys_pread64x(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_pread64x,self).__init__(batchCore)

        bytesRead = ConvertBatchCoreRetValue(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])
        aFilAcc.SetRead(bytesRead,self.m_core.m_parsedArgs[1])

class BatchLetSys_write(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_write,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])

        try:
            bytesWritten = int(self.m_core.m_retValue)
            aFilAcc.SetWritten(bytesWritten,self.m_core.m_parsedArgs[1])
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'write@SYS(28, "\\372", 1'
            pass

class BatchLetSys_writev(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_writev,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])

        try:
            bytesWritten = int(self.m_core.m_retValue)
            # The content is not processed yet.
            aFilAcc.SetWritten(bytesWritten,None)
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'write@SYS(28, "\\372", 1'
            pass

class BatchLetSys_ioctl(BatchLetBase,object):
    def __init__(self,batchCore):
        # With strace: "ioctl(-1, TIOCGPGRP, 0x7ffc3b5287f4) = -1 EBADF (Bad file descriptor)"
        # TODO: Could use the parameter TIOCSPGRP to get the process id: ioctl(255</dev/pts/2>, TIOCSPGRP, [26531])

        if batchCore.m_retValue.find("EBADF") >= 0 :
            return
        super( BatchLetSys_ioctl,self).__init__(batchCore)

        self.m_significantArgs = [ self.STraceStreamToFile( self.m_core.m_parsedArgs[0] ) ] + self.m_core.m_parsedArgs[1:0]

class BatchLetSys_stat(BatchLetBase,object):
    def __init__(self,batchCore):
        # TODO: If the stat is not successful, maybe it should be rejected.
        if InvalidReturnedFileDescriptor(batchCore.m_retValue,batchCore.m_tracer):
            return
        super( BatchLetSys_stat,self).__init__(batchCore)

        self.m_significantArgs = [ self.ToObjectPath_Accessed_CIM_DataFile( self.m_core.m_parsedArgs[0] ) ]

class BatchLetSys_lstat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_lstat,self).__init__(batchCore)

        self.m_significantArgs = [ self.ToObjectPath_Accessed_CIM_DataFile( self.m_core.m_parsedArgs[0] ) ]

# With ltrace:
# lstat@SYS("./UnitTests/mineit_wget_hotmail.strace.866.xml", 0x55fd19026230) = 0
# lgetxattr@SYS("./UnitTests/mineit_wget_hotmail.strace.866.xml", "security.selinux", 0x55fd19029770, 255) = 37
# getxattr@SYS("./UnitTests/mineit_wget_hotmail.strace.866.xml", "system.posix_acl_access", nil, 0) = -61




class BatchLetSys_access(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_access,self).__init__(batchCore)

        self.m_significantArgs = [ self.ToObjectPath_Accessed_CIM_DataFile( self.m_core.m_parsedArgs[0] ) ]

class BatchLetSys_dup(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_dup,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

        self.m_significantArgs.append( self.STraceStreamToFile( self.m_core.m_retValue ) )
        # TODO: BEWARE, DUPLICATED ELEMENTS IN THE ARGUMENTS: SHOULD sort()+uniq()

class BatchLetSys_dup2(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_dup2,self).__init__(batchCore)

        # TODO: After that, the second file descriptor points to the first one.
        self.m_significantArgs = self.StreamName()

##### Memory system calls.

class BatchLetSys_mmap(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return

        fdArg = batchCore.m_parsedArgs[4]
        if fdArg == "-1":
            return
        super( BatchLetSys_mmap,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName(4)

class BatchLetSys_munmap(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_munmap,self).__init__(batchCore)

        # The parameter is only an address and we cannot do much with it.
        self.m_significantArgs = []

# 'mmap2' ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'] ==>> 0xf7b21000 (09:18:26,09:18:26)
class BatchLetSys_mmap2(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLetSys_mmap2,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName(4)



##### File system calls.

class BatchLetSys_fstat(BatchLetBase,object):
    def __init__(self,batchCore):
        # With strace: "fstat(-1, 0x7fff57630980) = -1 EBADF (Bad file descriptor)"
        if batchCore.m_retValue.find("EBADF") >= 0 :
            return
        super( BatchLetSys_fstat,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fstat64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fstat64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fstatfs(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fstatfs,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fadvise64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fadvise64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fchdir(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fchdir,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

        # This also stores the new current directory in the process.
        self.m_core.m_objectProcess.SetProcessCurrentDir(self.m_significantArgs[0])

class BatchLetSys_fcntl(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fcntl,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fcntl64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fcntl64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fchown(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fchown,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_ftruncate(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_ftruncate,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fsync(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fsync,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fchmod(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fchmod,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


##### Process system calls.

# Two usual sets of flags:
# flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
# flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD
#

# CLONE_CHILD_CLEARTID Erase child thread ID at location ctid in child memory when the child exits, and do a wakeup on the futex at that address.
# CLONE_CHILD_SETTID Store child thread ID at location ctid in child memory.
# CLONE_FILES If CLONE_FILES is set, the calling process and the child process share the same file descriptor table.
# CLONE_FS the caller and the child process share the same file system information.
# CLONE_NEWIPC If CLONE_NEWIPC is set, then create the process in a new IPC namespace.
# CLONE_NEWNET If CLONE_NEWNET is set, then create the process in a new network namespace.
# CLONE_NEWNS Start the child in a new mount namespace.
# CLONE_NEWPID Create the process in a new PID namespace.
# CLONE_NEWUTS create the process in a new UTS namespace.
# CLONE_PARENT the parent of the new child (as returned by getppid(2)) will be the same as that of the calling process.
# CLONE_PARENT_SETTID Store child thread ID at location ptid in parent and child memory.
# CLONE_PID the child process is created with the same process ID as the calling process.
# CLONE_PTRACE If CLONE_PTRACE is specified, and the calling process is being traced, then trace the child also .
# CLONE_SETTLS The newtls argument is the new TLS (Thread Local Storage) descriptor.
# CLONE_SIGHAND If CLONE_SIGHAND is set, the calling process and the child process share the same table of signal handlers.
# CLONE_STOPPED the child is initially stopped (as though it was sent a SIGSTOP signal), and must be resumed by sending it a SIGCONT signal.
# CLONE_SYSVSEM the child and the calling process share a single list of System V semaphore undo values (see semop(2)).
# CLONE_THREAD the child is placed in the same thread group as the calling process.
# CLONE_UNTRACED a tracing process cannot force CLONE_PTRACE on this child process.
# CLONE_VFORK the execution of the calling process is suspended until the child releases its virtual memory resources via a call to execve(2) or _exit(2).
# CLONE_VM the calling process and the child process run in the same memory space.
class BatchLetSys_clone(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_clone,self).__init__(batchCore)

        # The process id is the return value but does not have the same format
        # with ltrace (hexadecimal) and strace (decimal).
        if batchCore.m_tracer == "ltrace":
            aPid = int(self.m_core.m_retValue,16)

            # TODO: How to make the difference between thread and process ?
            isThread = True
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core.m_retValue)
            flagsClone = self.m_core.m_parsedArgs[1].strip()
            if flagsClone.find("CLONE_VM") >= 0:
                isThread = True
            else:
                # flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD
                isThread = False
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core.m_retValue, aPid) )

        # This is the created process.
        objNewProcess = ToObjectPath_CIM_Process( aPid)

        if isThread:
            objNewProcess.SetThread()

        self.m_significantArgs = [ objNewProcess ]

        objNewProcess.AddParentProcess(self.m_core.m_timeStart,self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self,anotherBatch):
        return False

# It does not matter if the first "unfinished" cannot be found because only
# the "resumed" part is important as it constains the sub-PID/
class BatchLetSys_vfork(BatchLetBase,object):

    Incomplete_ResumedWithoutUnfinishedIsOk = True

    def __init__(self,batchCore):
        super( BatchLetSys_vfork,self).__init__(batchCore)

        # The process id is the return value but does not have the same format
        # with ltrace (hexadecimal) and strace (decimal).
        if batchCore.m_tracer == "ltrace":
            aPid = int(self.m_core.m_retValue,16)
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core.m_retValue)
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        # This is the created process.
        objNewProcess = ToObjectPath_CIM_Process( aPid )
        self.m_significantArgs = [ objNewProcess ]

        objNewProcess.AddParentProcess(self.m_core.m_timeStart,self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self,anotherBatch):
        return False

# This is detected by strace.
# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>

# This is detected by ltrace also, with several situation:
# execve@SYS("/usr/local/bin/as", 0xd1a138, 0xd1a2b0) = -2 <0.000243>
# execve@SYS("/usr/bin/as", 0xd1a138, 0xd1a2b0 <no return ...>
# execve@SYS("/usr/bin/wc", 0x55e291ac8950, 0x55e291ac8f00 <unfinished ...>

class BatchLetSys_execve(BatchLetBase,object):
    def __init__(self,batchCore):

        # strace:
        # ['/usr/lib64/qt-3.3/bin/grep', '[grep, toto, ..]'] ==>> -1 ENOENT (No such file or directory)
        # ltrace:
        # execve@SYS("/usr/bin/ls", 0x55e291ac9bd0, 0x55e291ac8830 <no return ...>
        # If the executable could not be started, no point creating a batch node.
        if batchCore.m_retValue.find("ENOENT") >= 0 :
            return
        super( BatchLetSys_execve,self).__init__(batchCore)

        # The first argument is the executable file name,
        # while the second is an array of command-line parameters.
        objNewDataFile = self.ToObjectPath_Accessed_CIM_DataFile(self.m_core.m_parsedArgs[0] )

        if batchCore.m_tracer == "ltrace":
            # This contains just a pointer so we reuse 
            commandLine = None # [ self.m_core.m_parsedArgs[0] ]
        elif batchCore.m_tracer == "strace":
            commandLine = self.m_core.m_parsedArgs[1]
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        self.m_significantArgs = [
            objNewDataFile,
            commandLine ]

        self.m_core.m_objectProcess.SetExecutable( objNewDataFile )
        self.m_core.m_objectProcess.SetCommandLine( commandLine )
        objNewDataFile.SetIsExecuted()

        # TODO: Specifically filter the creation of a new process.

    # Process creations or setup are not aggregated.
    def SameCall(self,anotherBatch):
        return False

# This is detected by ltrace.
# __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
# It does not matter if it is not technically finished: We only need the executable.
# BEWARE: See difference with BatchLetSys_xxx classes.
class BatchLetLib___libc_start_main(BatchLetBase,object):
    Incomplete_UnfinishedIsOk = True

    def __init__(self,batchCore):
        super( BatchLetLib___libc_start_main,self).__init__(batchCore)

        # TODO: Take the path of the executable name.
        commandLine = self.m_core.m_parsedArgs[0]
        execName = commandLine[0]
        objNewDataFile = self.ToObjectPath_Accessed_CIM_DataFile(execName)
        self.m_significantArgs = [
            objNewDataFile,
            commandLine ]
        self.m_core.m_objectProcess.SetExecutable( objNewDataFile )
        self.m_core.m_objectProcess.SetCommandLine( commandLine )
        objNewDataFile.SetIsExecuted()

    # Process creations or setup are not aggregated.
    def SameCall(self,anotherBatch):
        return False

class BatchLetSys_wait4(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_wait4,self).__init__(batchCore)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core.m_retValue, aPid) )

        # sys.stdout.write("WAIT A=%s\n" % self.m_core.m_retValue )
        # This is the terminated pid.
        if batchCore.m_tracer == "ltrace":
            if self.m_core.m_retValue.find("-10") >= 0:
                # ECHILD = 10
                # wait4@SYS(-1, 0x7ffea10cd110, 1, 0) = -10
                aPid = None
            else:
                # <... wait4 resumed> ) = 0x2df2 
                aPid = int(self.m_core.m_retValue,16)
                # sys.stdout.write("WAITzzz=%d\n" % aPid )
        elif batchCore.m_tracer == "strace":
            if self.m_core.m_retValue.find("ECHILD") >= 0:
                # wait4(-1, 0x7fff9a7a6cd0, WNOHANG, NULL) = -1 ECHILD (No child processes) 
                aPid = None
            else:
                # <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 27037 
                try:
                    aPid = int(self.m_core.m_retValue.split(" ")[0])
                except ValueError:
                    sys.stdout.write("wait4: Cannot decode pid from:%s\n" % self.m_core.m_retValue)
                    aPid = None
                # sys.stdout.write("WAITxxx=%d\n" % aPid )
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        if aPid:
            # sys.stdout.write("WAIT=%d\n" % aPid )
            waitedProcess = ToObjectPath_CIM_Process( aPid )
            self.m_significantArgs = [ waitedProcess ]
            waitedProcess.WaitProcessEnd(self.m_core.m_timeStart, self.m_core.m_objectProcess)

class BatchLetSys_exit_group(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_exit_group,self).__init__(batchCore)

        self.m_significantArgs = []

#####

# int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
class BatchLetSys_newfstatat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_newfstatat,self).__init__(batchCore)

        dirNam = self.m_core.m_parsedArgs[0]

        if dirNam == "AT_FDCWD":
            dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
        else:
            dirPath = STraceStreamToPathname( dirNam )
            if not dirPath:
                raise Exception("Invalid directory:%s"%dirNam)

        filNam = self.m_core.m_parsedArgs[1]

        pathName = ToAbsPath( dirPath, filNam )

        self.m_significantArgs = [ self.ToObjectPath_Accessed_CIM_DataFile(pathName) ]

class BatchLetSys_getdents(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getdents,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_getdents64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getdents64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

##### Sockets system calls.

class BatchLetSys_sendmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_sendmsg,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# sendmmsg(3<socket:[535040600]>, {{{msg_name(0)=NULL, msg_iov(1)=[{"\270\32\1\0\0\1\0\0
class BatchLetSys_sendmmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_sendmmsg,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_recvmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_recvmsg,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# recvfrom(3<socket:[535040600]>, "\270\32\201\203\0\1\0\0\0\1\0\0\
class BatchLetSys_recvfrom(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_recvfrom,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# getsockname(1<TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]>, {sa_family=AF_INET6, sin6_port=htons(21), inet_pton(AF_INET6, "::ffff:54.36.162.150", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [28]) = 0 <0.000008>
class BatchLetSys_getsockname(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getsockname,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# getpeername(1<TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]>, {sa_family=AF_INET6, sin6_port=htons(63703), inet_pton(AF_INET6, "::ffff:82.45.12.63", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [28]) = 0 <0.000007>
class BatchLetSys_getpeername(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getpeername,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# ['[{fd=5<UNIX:[73470->73473]>, events=POLLIN}]', '1', '25000'] ==>> 1 ([{fd=5, revents=POLLIN}])
class BatchLetSys_poll(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_poll,self).__init__(batchCore)

        arrStrms = self.m_core.m_parsedArgs[0]


        if batchCore.m_tracer == "strace":
            if type(arrStrms) in (list, tuple):
                retList = []
                for oneStream in arrStrms:
                    # oneStream: {'fd=5<anon_inode:[eventfd]>', 'events=POLLIN'}
                    for elt in oneStream:
                        if elt.startswith('fd='):
                            fdName = elt[3:]
                            break

                filOnly = self.STraceStreamToFile( fdName )
                retList.append( filOnly )
                self.m_significantArgs = [ retList ]
            else:
                # It might be the string "NULL":
                sys.stdout.write("poll: Unexpected arrStrms=%s\n" % str(arrStrms) )
                self.m_significantArgs = []
        else:
            self.m_significantArgs = []

# int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
#
# If strace:
# select ['1', ['0</dev/pts/2>'], [], ['0</dev/pts/2>'], {'tv_sec': '0', 'tv_usec': '0'}] ==>> 0 (Timeout) (07:43:14,07:43:14)
# select(13, [0<TCPv6:[:::21]> 12<pipe:[10567127]>], NULL, NULL, {tv_sec=30, tv_usec=0}) = 1 (in [12], left {tv_sec=29, tv_usec=999997})
# If strace and kill -9:
# "select(1, [0</dev/pts/2>], [], [0</dev/pts/2>], NULL <unfinished ...>)"
#
# If ltrace and kill -9 the process:
# "select@SYS(1, 0x7ffd06327760, 0x7ffd063277e0, 0x7ffd06327860 <no return ...>"
class BatchLetSys_select(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_select,self).__init__(batchCore)

        if batchCore.m_tracer == "strace":
            def ArrFdNameToArrString(arrStrms):
                # The program strace formats the parameters of the system call select(), as three arrays
                # of file descriptors, each of them starting with the number, followed by the path name.
                if arrStrms == "NULL":
                    # If the array of file descriptors is empty.
                    return []
                else:
                    # The delimiter is a space:
                    # "1 arrStrms=['0<TCPv6:[:::21]> 12<pipe:[10567127]>']"
                    # sys.stdout.write("%d arrStrms=%s\n"%(len(arrStrms),str(arrStrms)))
                    filStrms = []
                    for fdName in arrStrms:
                        # Most of times there should be one element only.
                        splitFdName = fdName.split(" ")
                        for oneFdNam in splitFdName:
                            filStrms.append(self.STraceStreamToFile( oneFdNam ))
                    return filStrms

            arrArgs = self.m_core.m_parsedArgs
            arrFilRead = ArrFdNameToArrString(arrArgs[1])
            arrFilWrit = ArrFdNameToArrString(arrArgs[2])
            arrFilExcp = ArrFdNameToArrString(arrArgs[3])

            self.m_significantArgs = [ arrFilRead, arrFilWrit, arrFilExcp ]
        elif batchCore.m_tracer == "ltrace":
            self.m_significantArgs = []
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

class BatchLetSys_setsockopt(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_setsockopt,self).__init__(batchCore)

        self.m_significantArgs = [ self.m_core.m_retValue ]

# socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 6<UNIX:[2038057]>
class BatchLetSys_socket(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_socket,self).__init__(batchCore)

        self.m_significantArgs = [ self.STraceStreamToFile(self.m_core.m_retValue) ]

# Different output depending on the tracer:
# strace: connect(6<UNIX:[2038057]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)
# ltrace: connect@SYS(3, 0x25779f0, 16, 0x1999999999999999)
class BatchLetSys_connect(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_connect,self).__init__(batchCore)
        objPath = self.STraceStreamToFile(self.m_core.m_parsedArgs[0])

        if batchCore.m_tracer == "strace":
            # 09:18:26.465799 socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP) = 3 <0.000013>
            # 09:18:26.465839 connect(3<socket:[535040600]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0 <0.000016>

            # TODO: Should link this file descriptor to the IP-addr+port pair.
            # But this is not very important because strace does the job of remapping the file descriptor,
            # so things are consistent as long as we follow the same logic, in the same order:
            #    socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3<TCP:[7275805]>
            #    connect(3<TCP:[7275805]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("204.79.197.212")}, 16) = 0
            #    select(4, NULL, [3<TCP:[192.168.0.17:48318->204.79.197.212:80]>], NULL, {900, 0}) = 1
            objPath.SocketAddress = self.m_core.m_parsedArgs[1]
            
        elif batchCore.m_tracer == "ltrace":
            pass
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

        self.m_significantArgs = [ objPath ]
class BatchLetSys_bind(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_bind,self).__init__(batchCore)
        objPath = self.STraceStreamToFile(self.m_core.m_parsedArgs[0])
        if batchCore.m_tracer == "strace":
            # bind(4<NETLINK:[7274795]>, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 0
            objPath.SocketAddress = self.m_core.m_parsedArgs[1]

        elif batchCore.m_tracer == "ltrace":
            pass
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

        self.m_significantArgs = [ objPath ]

# sendto(7<UNIX:[2038065->2038073]>, "\24\0\0", 16, MSG_NOSIGNAL, NULL, 0) = 16
class BatchLetSys_sendto(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_sendto,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_pipe,self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = self.STraceStreamToFile(arrPipes[0])
        arrFil1 = self.STraceStreamToFile(arrPipes[1])

        self.m_significantArgs = [ arrFil0, arrFil1 ]

# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe2(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_pipe2,self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = self.STraceStreamToFile(arrPipes[0])
        arrFil1 = self.STraceStreamToFile(arrPipes[1])

        self.m_significantArgs = [ arrFil0, arrFil1 ]


class BatchLetSys_shutdown(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_shutdown,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

#####
        
# This is detected by ltrace.
# There can be several types of instantiations:
# libaugeas.so.0->getenv("HOME")            = "/home/rchateau"
# libaugeas.so.0->getenv("XDG_CACHE_HOME")  = nil
# libclntsh.so.11.1->getenv("HOME")         = "/home/rchateau"
# libclntsh.so.11.1->getenv("ORACLE_HOME")  = "/u01/app/oracle/product/11.2.0/xe"
# libpython2.7.so.1.0->getenv("PYTHONHOME") = nil
#
# This assumes that all shared libraries instianting a function with this same
# are actually doing the same thing. This might be wrong.
class BatchLetLib_getenv(BatchLetBase,object):

    def __init__(self,batchCore):
        # We could also take the environment variables of each process but
        # It does not tell which ones are actually useful.
        global G_EnvironmentVariables

        # The base class is never created because we do not need it.
        # We just need to intercept the environment variables reading.
        # super( BatchLetLib_getenv,self).__init__(batchCore)

        envNam = batchCore.m_parsedArgs[0]
        envVal = batchCore.m_retValue
        if envVal == "nil":
            envVal = ""
        
        # FIXME: Should have one map per process ?
        G_EnvironmentVariables[envNam] = envVal
        

#F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python', '', '4096'] ==>> 7 (16:42:10,16:42:10)
#F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2', 'python2', '4096'] ==>> 9 (16:42:10,16:42:10)
#F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2.7', 'python2.7', '4096'] ==>> -22 (16:42:10,16:42:10)

################################################################################

class UnfinishedBatches:
    def __init__(self,withWarning):
        # This must be specific to processes.
        # Because when a system call is resumed, it is in the same process.
        self.m_mapStacks = {}
        self.m_withWarning = withWarning


    # PROBLEM. A vfork() is started in the main process but "appears" in another one.
    # What we could do is infer the main process number when a pid appreas without having been created before.
    # 08:53:31.301860 vfork( <unfinished ...>
    # [pid 23944] 08:53:31.304901 <... vfork resumed> ) = 23945 <0.003032>



    def PushBatch(self,batchCoreUnfinished):
        # sys.stdout.write("PushBatch pid=%s m_funcNam=%s\n"%(batchCoreUnfinished.m_pid,batchCoreUnfinished.m_funcNam))
        try:
            mapByPids = self.m_mapStacks[ batchCoreUnfinished.m_pid ]
            try:
                mapByPids[ batchCoreUnfinished.m_funcNam ].append( batchCoreUnfinished )
            except KeyError:
                mapByPids[ batchCoreUnfinished.m_funcNam ] = [ batchCoreUnfinished ]
        except KeyError:
            self.m_mapStacks[ batchCoreUnfinished.m_pid ] = { batchCoreUnfinished.m_funcNam : [ batchCoreUnfinished ] }
            
        # sys.stdout.write("PushBatch m_funcNam=%s\n"%batchCoreUnfinished.m_funcNam)

    def MergePopBatch(self,batchCoreResumed):
        # sys.stdout.write("MergePopBatch pid=%s m_funcNam=%s\n"%(batchCoreResumed.m_pid,batchCoreResumed.m_funcNam))
        try:
            stackPerFunc = self.m_mapStacks[ batchCoreResumed.m_pid][ batchCoreResumed.m_funcNam ]
        except KeyError:
            if self.m_withWarning > 1:
                sys.stdout.write("Resuming %s: cannot find unfinished call\n"%batchCoreResumed.m_funcNam)

            # This is strange, we could not find the unfinished call.
            # sys.stdout.write("MergePopBatch NOTFOUND1 m_funcNam=%s\n"%batchCoreResumed.m_funcNam)
            return None

        # They should have the same pid.
        try:
            batchCoreUnfinished = stackPerFunc[-1]
        except IndexError:
            if self.m_withWarning > 1:
                sys.stdout.write("MergePopBatch pid=%d m_funcNam=%s cannot find call\n"
                    % (batchCoreResumed.m_pid,batchCoreResumed.m_funcNam) )
            # Same problem, we could not find the unfinished call.
            # sys.stdout.write("MergePopBatch NOTFOUND2 m_funcNam=%s\n"%batchCoreResumed.m_funcNam)
            return None

        del stackPerFunc[-1]

        # Sanity check
        if batchCoreUnfinished.m_funcNam != batchCoreResumed.m_funcNam:
            raise Exception("Inconsistency batchCoreUnfinished.m_funcNam=%s batchCoreResumed.m_funcNam=%s\n"
                % ( batchCoreUnfinished.m_funcNam, batchCoreResumed.m_funcNam ) )

        # Now, the unfinished and the resumed batches are merged.
        argsMerged = batchCoreUnfinished.m_parsedArgs + batchCoreResumed.m_parsedArgs
        batchCoreResumed.m_parsedArgs = argsMerged

        # Sanity check
        if batchCoreUnfinished.m_status != BatchStatus.unfinished:
            raise Exception("Unfinished status is not plain:%d"%batchCoreUnfinished.m_status)

        batchCoreUnfinished.m_status = BatchStatus.matched
        batchCoreUnfinished.m_resumedBatch = batchCoreResumed

        # Sanity check
        if batchCoreResumed.m_status != BatchStatus.resumed:
            raise Exception("Resumed status is not plain:%d"%batchCoreResumed.m_status)

        batchCoreResumed.m_status = BatchStatus.merged
        batchCoreResumed.m_unfinishedBatch = batchCoreUnfinished

        return batchCoreResumed

    def PrintUnfinished(self,strm):
        if self.m_withWarning == 0:
            return
        for onePid in self.m_mapStacks:
            # strm.write("onePid=%s\n"%onePid)
            mapPid = self.m_mapStacks[ onePid ]

            isPidWritten = False
            
            for funcNam in mapPid:
                arrCores = mapPid[funcNam]
                if not arrCores: break

                if not isPidWritten:
                    isPidWritten = True
                    strm.write("Unfinished calls pid=%s\n"%onePid)

                strm.write("    Call name=%s\n"%funcNam)
                arrCores = mapPid[funcNam]
                for batchCoreUnfinished in arrCores:
                    strm.write("        %s\n" % ( batchCoreUnfinished.AsStr() ) )
                strm.write("\n")
        strm.write("\n")

# This is used to collect system or function calls which are unfinished and cannot be matched
# with the corresponding "resumed" line. In some circumstances, the beginning of a "wait4()" call
# might appear in one process, and the resumed part in another. Therefore this container 
# is global for all processes. The "withWarning" flag allows to hide detection of unmatched calls.
G_stackUnfinishedBatches = None

# There are displayed once only.
G_UnknownFunctions = set()

def BatchLetFactory(batchCore):

    try:
        # TODO: We will have to take the library into account.
        aModel = G_batchModels[ batchCore.m_funcNam ]
    except KeyError:
        # Default generic BatchLet, if the function is not associated to a derived class of BatchLetCore.
        if not batchCore.m_funcNam in G_UnknownFunctions:
            sys.stdout.write("Undefined function %s\n"%batchCore.m_funcNam)

            # Py_Main
            # readlink@SYS
            # getcwd@SYS
            # statfs@SYS
            # Py_Main@SYS
            # _llseek@SYS
            # madvise@SYS
            # _exit@SYS
            # prlimit64@SYS
            # ******->getenv
            # setrlimit@SYS
            # getrusage@SYS
            # unlink@SYS
            # umask@SYS
            # chmod@SYS
            # uname@SYS
            # times@SYS
            # mkdir@SYS
            # clock_gettime@SYS
            # sched_getaffinity@SYS
            # gettid@SYS
            # pipe2@SYS
            # getsockopt@SYS
            # clock_getres@SYS
            # getresuid@SYS
            # getresgid@SYS

            G_UnknownFunctions.add(batchCore.m_funcNam)
        return BatchLetBase( batchCore )

    # Explicitely non-existent.
    if aModel == None:
        return None

    # If this is an unfinished system call, it is not possible to build the correct derived class.
    # Until the pair of unfinished and resumed BatchCore-s are merged, this simply creates a generic base class.
    # [pid 12753] 14:56:54.296251 read(3 <unfinished ...>
    # [pid 12753] 14:56:54.296765 <... read resumed> , "#!/usr/bin/bash\n\n# Different ste"..., 131072) = 533 <0.000513>

    if batchCore.m_status == BatchStatus.unfinished:

        # A function as __libc_start_main() is happy if it is not finished
        # as the input parameters contain enough information for us.
        try:
            aModel.Incomplete_UnfinishedIsOk
            btchLetDrv = aModel( batchCore )
            # ResumedOnly
            # UnfinishedOnly
        except AttributeError:
            # We do not have the return value, and maybe not all the arguments,
            # so we simply store what we have and hope to merge
            # with the "resumed" part, later on.
            btchLetDrv = BatchLetBase( batchCore )

            # To match later with the "resumed" line.
            G_stackUnfinishedBatches.PushBatch( batchCore )
    elif batchCore.m_status == BatchStatus.resumed:
        # We should have the "unfinished" part somewhere.

        batchCoreMerged = G_stackUnfinishedBatches.MergePopBatch( batchCore )
        
        if batchCoreMerged:
            assert batchCoreMerged == batchCore
            try:
                btchLetDrv = aModel( batchCoreMerged )
            except:
                sys.stdout.write("Cannot create derived class %s from args:%s\n" % ( aModel.__name__,str(batchCore.m_parsedArgs)))
                raise
        else:
            # Could not find the matching unfinished batch.
            # Still we try the degraded mode if it is available.
            try:
                aModel.Incomplete_ResumedWithoutUnfinishedIsOk
                btchLetDrv = aModel( batchCore )
            except AttributeError:
                pass

            btchLetDrv = BatchLetBase( batchCore )
    else:
        btchLetDrv = aModel( batchCore )

    # If the parameters makes it unusable anyway.
    try:
        btchLetDrv.m_core
        # sys.stdout.write("batchCore=%s\n"%id(batchCore))
        assert btchLetDrv.m_core == batchCore
        return btchLetDrv
    except AttributeError:
        return None

################################################################################


# This groups several contiguous BatchLet which form a logical operation.
# For example (If the argument is factorised).:
#   Read(x)
#   Write(x)
#
# ... or ...
#   fseek("dummy.txt")
#   fwrite("dummy.txt")
#
# There can be several way to "reuse" a sequence, depending on other similar
# sequences.
#
class BatchLetSequence(BatchLetBase,object):
    def __init__(self,arrBatch,style):
        batchCore = BatchLetCore()

        # TODO: Instead of a string, this could be a tuple because it is hashable.
        concatSigns = "+".join( [ btch.GetSignature() for btch in arrBatch ] )
        batchCore.m_funcNam = "(" + concatSigns + ")"

        batchCore.m_status = BatchStatus.sequence

        # sys.stdout.write("BatchLetSequence concatSigns=%s\n"%concatSigns)

        # This is returned by the method SignificantArgs()

        # Cannot use a set because lists are not hashable, and objects always different.
        # Because there are very few arguments, it is allright to iterate on each list.
        argsArray = []
        for btch in arrBatch:
            for oneArg in btch.SignificantArgs():
                if not oneArg in argsArray:
                    argsArray.append( oneArg )
        batchCore.m_parsedArgs = argsArray

        # All batchlets should have the same pid.
        batchCore.m_pid = arrBatch[0].m_core.m_pid

        batchCore.m_timeStart = arrBatch[0].m_core.m_timeStart
        batchCore.m_timeEnd = arrBatch[-1].m_core.m_timeEnd
        batchCore.m_execTim = datetime.datetime.strptime(batchCore.m_timeEnd, '%H:%M:%S.%f') - datetime.datetime.strptime(batchCore.m_timeStart, '%H:%M:%S.%f')

        super( BatchLetSequence,self).__init__(batchCore,style)



def SignatureForRepetitions(batchRange):
    return "+".join( [ aBtch.GetSignatureWithArgs() for aBtch in batchRange ] )


BatchDumpersDictionary = {
    "TXT": BatchDumperTXT,
    "CSV": BatchDumperCSV,
    "JSON": BatchDumperJSON
}


# This is an execution flow, associated to a process. And a thread ?
class BatchFlow:
    def __init__(self):

        self.m_listBatchLets = []
        self.m_coroutine = self.AddingCoroutine()
        next(self.m_coroutine)

    def AddBatch(self,btchLet):
        # sys.stdout.write("AddBatch:%s\n"%btchLet.GetSignature())
        numBatches = len(self.m_listBatchLets)

        if numBatches > 0:
            lstBatch = self.m_listBatchLets[-1]

            if lstBatch.SameCall( btchLet ):
                lstBatch.m_occurrences += 1
                return

        self.m_listBatchLets.append( btchLet )

    # Does the same AddBatch() but it is possible to process system calls on-the-fly
    # without intermediate storage.
    def SendBatch(self,btchLet):
        self.m_coroutine.send(btchLet)

    def AddingCoroutine(self):
        lstBatch = None
        while True:
            btchLet = yield
            
            if lstBatch and lstBatch.SameCall( btchLet ):
                lstBatch.m_occurrences += 1
            else:
                self.m_listBatchLets.append( btchLet )
            # Intentionally points to the object actually stored in the container,
            # instead of the possibly transient object returned by yield.
            lstBatch = self.m_listBatchLets[-1]
                
        

    # This removes matched batches (Formerly unfinished calls which were matched to the resumed part)
    # when the merged batches (The resumed calls) comes immediately after.
    def FilterMatchedBatches(self):
        lenBatch = len(self.m_listBatchLets)

        numSubst = 0
        idxBatch = 1
        while idxBatch < lenBatch:
            # sys.stdout.write("FilterMatchedBatches idxBatch=%d\n"%( idxBatch ) )
            batchSeq = self.m_listBatchLets[idxBatch]
            batchSeqPrev = self.m_listBatchLets[idxBatch-1]

            # Sanity check.
            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged:
                if batchSeqPrev.m_core.m_funcNam != batchSeq.m_core.m_funcNam :
                    raise Exception("INCONSISTENCY1 %s %s\n"% ( batchSeq.m_core.m_funcNam, batchSeqPrev.m_core.m_funcNam ) )

            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged:
                if batchSeqPrev.m_core.m_resumedBatch.m_unfinishedBatch != batchSeqPrev.m_core:
                    raise Exception("INCONSISTENCY2 %s\n"% batchSeqPrev.m_core.m_funcNam)

            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged:
                if batchSeq.m_core.m_unfinishedBatch.m_resumedBatch != batchSeq.m_core:
                    raise Exception("INCONSISTENCY3 %s\n"% batchSeq.m_core.m_funcNam)

            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged \
            and batchSeqPrev.m_core.m_resumedBatch == batchSeq.m_core \
            and batchSeq.m_core.m_unfinishedBatch == batchSeqPrev.m_core :
                del self.m_listBatchLets[idxBatch-1]
                batchSeq.m_core.m_unfinishedBatch = None
                lenBatch -= 1
                numSubst += 1

            idxBatch += 1
            
        return numSubst

    # This counts the frequency of consecutive pairs of calls.
    # Used to replace these common pairs by an aggregate call.
    # See https://en.wikipedia.org/wiki/N-gram about bigrams.
    # About statistics: https://books.google.com/ngrams/info
    def StatisticsBigrams(self):

        lenBatch = len(self.m_listBatchLets)

        mapOccurences = {}

        idxBatch = 0
        maxIdx = lenBatch - 1
        while idxBatch < maxIdx:
            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + 2 ]

            keyRange = SignatureForRepetitions( batchRange )

            try:
                mapOccurences[ keyRange ] += 1
            except KeyError:
                mapOccurences[ keyRange ] = 1
            idxBatch += 1

        return mapOccurences

    # This examines pairs of consecutive calls with their arguments, and if a pair
    # occurs often enough, it is replaced by a single BatchLetSequence which represents it.
    def ClusterizeBigrams(self):
        lenBatch = len(self.m_listBatchLets)

        mapOccurences = self.StatisticsBigrams()

        numSubst = 0
        idxBatch = 0
        maxIdx = lenBatch - 1
        batchSeqPrev = None
        while idxBatch < maxIdx:

            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + 2 ]
            keyRange = SignatureForRepetitions( batchRange )
            numOccur = mapOccurences.get( keyRange, 0 )

            # sys.stdout.write("ClusterizeBigrams keyRange=%s numOccur=%d\n" % (keyRange, numOccur) )

            # Five occurences for example, as representative of a repetition.
            if numOccur > 5:
                batchSequence = BatchLetSequence( batchRange, "Rept" )

                # Maybe it is the same as the previous element, if this is a periodic pattern.
                if batchSeqPrev and batchSequence.SameCall( batchSeqPrev ):
                    # Simply reuse the previous batch.
                    batchSeqPrev.m_occurrences += 1
                    del self.m_listBatchLets[ idxBatch : idxBatch + 2 ]
                    maxIdx -= 2
                else:
                    self.m_listBatchLets[ idxBatch : idxBatch + 2 ] = [ batchSequence ]
                    maxIdx -= 1
                    batchSeqPrev = batchSequence
                    idxBatch += 1

                numSubst += 1
            else:
                batchSeqPrev = None
                idxBatch += 1
            
        return numSubst

    # Successive calls which have the same arguments are clusterized into logical entities.
    def ClusterizeBatchesByArguments(self):
        lenBatch = len(self.m_listBatchLets)

        numSubst = 0
        idxLast = 0
        idxBatch = 1
        while idxBatch <= lenBatch:
            if idxBatch < lenBatch:
                lastBatch = self.m_listBatchLets[ idxLast ]
                lastArgs = lastBatch.SignificantArgs()
                if not lastArgs:
                    idxLast += 1
                    idxBatch += 1
                    continue

                currentBatch = self.m_listBatchLets[ idxBatch ]

                if currentBatch.SignificantArgs() == lastArgs:
                    idxBatch += 1
                    continue

            if idxBatch > idxLast + 1:

                # Clusters should not be too big
                batchSeq = BatchLetSequence( self.m_listBatchLets[ idxLast : idxBatch ], "Args" )
                self.m_listBatchLets[ idxLast : idxBatch ] = [ batchSeq ]

                lenBatch -= ( idxBatch - idxLast - 1 )
                numSubst += 1

            idxLast += 1
            idxBatch = idxLast + 1
        return numSubst

    def DumpFlowInternal(self, batchDump, extra_header = None):
        batchDump.Header(extra_header)
        for aBtch in self.m_listBatchLets:
            batchDump.DumpBatch(aBtch)
        batchDump.Footer()

    def DumpFlowSimple(self, strm, outputFormat):
        batchConstructor = BatchDumpersDictionary[outputFormat]
        batchDump = batchConstructor(strm)
        self.DumpFlowInternal(batchDump)

    def DumpFlowConstructor(self, batchDump, extra_header = None):
        self.DumpFlowInternal(batchDump)

    def FactorizeOneFlow(self,verbose,withWarning,outputFormat):

        if verbose > 1: self.DumpFlowSimple(sys.stdout,outputFormat)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("FilterMatchedBatches lenBatch=%d\n"%(len(self.m_listBatchLets)) )
        numSubst = self.FilterMatchedBatches()
        if verbose > 0:
            sys.stdout.write("FilterMatchedBatches numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

        idxLoops = 0
        while True:
            if verbose > 1:
                self.DumpFlowSimple(sys.stdout,outputFormat)

            if verbose > 0:
                sys.stdout.write("\n")
                sys.stdout.write("ClusterizeBigrams lenBatch=%d\n"%(len(self.m_listBatchLets)) )
            numSubst = self.ClusterizeBigrams()
            if verbose > 0:
                sys.stdout.write("ClusterizeBigrams numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )
            if numSubst == 0:
                break
            idxLoops += 1

        if verbose > 1: self.DumpFlowSimple(sys.stdout,outputFormat)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("ClusterizeBatchesByArguments lenBatch=%d\n"%(len(self.m_listBatchLets)) )
        numSubst = self.ClusterizeBatchesByArguments()
        if verbose > 0:
            sys.stdout.write("ClusterizeBatchesByArguments numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

        if verbose > 1: self.DumpFlowSimple(sys.stdout,outputFormat)


# Logging execution information.
def LogSource(msgSource):
    sys.stdout.write("Parameter:%s\n"%msgSource)

################################################################################

# This executes a Linux command and returns the stderr pipe.
# It is used to get the return content of strace or ltrace,
# so it can be parsed.
def GenerateLinuxStreamFromCommand(raw_command, aPid):
    aCmd = [str(elt) for elt in raw_command]
    assert isinstance(aPid, int)
    sys.stdout.write("Starting trace command:%s\n" % " ".join(aCmd) )

    # If shell=True, the command must be passed as a single line.
    kwargs = {"bufsize":100000, "shell":False,
        "stdin":sys.stdin, "stdout":subprocess.PIPE, "stderr":subprocess.PIPE}
    if sys.version_info >= (3,):
        kwargs["encoding"] = "utf-8"
    pipPOpen = subprocess.Popen(aCmd, **kwargs)

    # If shell argument is True, this is the process ID of the spawned shell.
    if aPid > 0:
        # The process already exists and strace/ltrace attaches to it.
        thePid = aPid
    else:
        # We want the pid of the process created by strace/ltrace.
        # ltrace always prefixes each line with the pid, so no ambiguity.
        # strace does not always prefixes the top process calls with the pid.
        thePid = int(pipPOpen.pid)

    return ( thePid, pipPOpen.stderr )

# This applies to strace and ltrace.
# It isolates single lines describing an individual function or system call.
def CreateFlowsFromGenericLinuxLog(verbose,logStream,tracer):

    # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
    # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
    # This test is not reliable because we cannot really control what a spurious output can be:
    def IsLogEnding(aLin):
        if aLin.endswith(">\n"):
            ixLT = aLin.rfind("<")
            if ixLT >= 0:
                strBrack = aLin[ixLT+1:-2]
                try:
                    flt = float(strBrack)
                    return True
                except:
                    pass

                if strBrack == "unfinished ...":
                    return True

                # This value occurs exclusively with ltrace. Examples:
                # exit_group@SYS(0 <no return ...>
                # execve@SYS("/usr/bin/as", 0xd1a138, 0xd1a2b0 <no return ...>
                if strBrack == "no return ...":
                    return True
        else:
            # "[pid 18194] 08:26:47.197005 exit_group(0) = ?"
            # Not reliable because this could be a plain string ending like this.
            if aLin.startswith("[pid ") and aLin.endswith(" = ?\n"):
                return True

            # "08:26:47.197304 --- SIGCHLD {si_signo=SIGCHLD, si_status=0, si_utime=0, si_stime=0} ---"
            # Not reliable because this could be a plain string ending like this.
            if aLin.endswith(" ---\n"):
                return True

        return False


    # This is parsed from each line corresponding to a syztem call.
    batchCore = None

    lastTimeStamp = 0

    numLine = 0
    oneLine = ""
    while True:
        prevLine = oneLine
        oneLine = ""

        # There are several cases of line ending with strace.
        # If a function has a string parameter which contain a carriage-return,
        # this is not filtered and this string is split on multiple lines.
        # We cannot reliably count the double-quotes.
        # FIXME: Problem if several processes.
        while not G_Interrupt:
            # sys.stdout.write("000:\n")
            tmpLine = logStream.readline()
            # sys.stdout.write("AAA:%s"%tmpLine)
            numLine += 1
            # sys.stdout.write("tmpLine after read=%s"%tmpLine)
            if not tmpLine:
                break

            # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
            # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
            # This test is not reliable because we cannot really control what a spurious output can be:
            if IsLogEnding( tmpLine ):
                # TODO: The most common case is that the call is on one line only.
                oneLine += tmpLine
                break

            # If the call is split on several lines, maybe because a write() contains a "\n".
            oneLine += tmpLine[:-1]

        if not oneLine:
            # If this is the last line and therefore the last call.
            sys.stdout.write("Last line=%s\n"%prevLine)

            # This is the terminate date of the last process still running.
            if lastTimeStamp:
                CIM_Process.GlobalTerminationDate(lastTimeStamp)

            break

        # This parses the line into the basic parameters of a function call.
        try:
            batchCore = CreateBatchCore(oneLine,tracer)
        except:
            if numLine == 2:
                # If the command does not exist:
                # "strace: Can't stat 'qklsjhdflksd': No such file or directory"
                # "Can't open qklsjhdflksd: No such file or directory"
                if oneLine.find("No such file or directory") >= 0:
                    raise Exception("Invalid command: %s" % oneLine)

                # If the pid is invalid, the scond contains "No such process"
                # "strace: attach: ptrace(PTRACE_SEIZE, 11111): No such process"
                # "Cannot attach to pid 11111: No such process"
                if oneLine.find("No such process") >= 0:
                    raise Exception("Invalid process id: %s" % oneLine)

            sys.stderr.write("Caught invalid line %d:%s\n"%(numLine,oneLine) )
            # raise

        # Maybe the line cannot be parsed.
        if batchCore:

            lastTimeStamp = batchCore.m_timeEnd

            # This creates a derived class deduced from the system call.
            try:
                aBatch = BatchLetFactory(batchCore)
            except:
                sys.stdout.write("Line:%d Error parsing:%s"%(numLine,oneLine))
                raise

            # Some functions calls should simply be forgotten because there are
            # no side effects, so simply forget them.
            if aBatch:
                yield aBatch

################################################################################

# These libc calls can be detected by ltrace but must be filtered
# because they do not bring information we want (And there are loads of them
# These libc calls can be detected by ltrace but must be filtered
# because they do not bring information we want (And there are loads of them))
G_ignoredCallLTrace = [
    "strncmp",
    "strlen",
    "malloc",
    "strcmp",
    "memcmp",
    "memcpy",
    "calloc",
    "malloc",
    "free",
    "memset",
    "strcasecmp",
    "__strdup",
    "strchr",
    "sprintf",
    "__errno_location",
    "bfd*",
    "fopen",
]

# Many libc calls are created by several libraries because they are static.
# For example:
#    gcc->getenv("GNUTARGET") = nil <0.000182>
#    liblto_plugin.so.0->getenv("COLLECT_GCC_OPTIONS") = "'-mtune=generic' '-march=x86-64'" <0.000321>
# Note that the results are visible.
#
# Also, there are many libc calls, and in general, we do not know how to process
# their arguments.
# So we filter them additively.

# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildLTraceCommand(extCommand,aPid):

    # This selects:
    # libpython2.7.so.1.0->getenv, cx_Oracle.so->getenv, libclntsh.so.11.1->getenv, libresolv.so.2->getenv etc...
    strMandatoryLibc = "-*+getenv+*@SYS"

    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    # This needs long strings because path names are truncated like normal strings.
    aCmd = ["ltrace",
        "-tt", "-T", "-f", "-S", "-s", G_StringSize,
        "-e", strMandatoryLibc
        ]

    # Example of log: This can be filtered with: "-e -realpath"
    # gcc->realpath(0x2abfbe0, 0x7ffd739d8310, 0x2ac0930, 0 <unfinished ...>
    # lstat@SYS("/usr", 0x7ffd739d8240)                    = 0 <0.000167>
    # lstat@SYS("/usr/local", 0x7ffd739d8240)              = 0 <0.000118>
    # lstat@SYS("/usr/local/include", 0x7ffd739d8240)      = 0 <0.000162>
    # lstat@SYS("/usr/local/include/bits", 0x7ffd739d8240) = -2 <0.000177>
    # <... realpath resumed> )                             = 0 <0.001261>

    if extCommand:
        aCmd += extCommand
    else:
        aCmd += [ "-p", aPid ]

    return aCmd

def LogLTraceFileStream(extCommand,aPid):
    aCmd = BuildLTraceCommand( extCommand, aPid )
    if extCommand:
        LogSource("Command "+" ".join(extCommand) )
    else:
        LogSource("Process %s\n"%aPid)
    return GenerateLinuxStreamFromCommand(aCmd, aPid)


# The output log format of ltrace is very similar to strace's, except that:
# - The system calls are suffixed with "@SYS" or prefixed with "SYS_"
# - Entering and leaving a shared library is surrounded by the lines:
# ...  Py_Main(...  <unfinished ...>
# ...  <... Py_Main resumed> ) 
# - It does not print the path of file descriptors.

# [pid 28696] 08:50:25.573022 rt_sigaction@SYS(33, 0x7ffcbdb8f840, 0, 8) = 0 <0.000032>
# [pid 28696] 08:50:25.573070 rt_sigprocmask@SYS(1, 0x7ffcbdb8f9b8, 0, 8) = 0 <0.000033>
# [pid 28696] 08:50:25.573127 getrlimit@SYS(3, 0x7ffcbdb8f9a0) = 0 <0.000028>
# [pid 28696] 08:50:25.576494 __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py"... ] <unfinished ...>
# [pid 28696] 08:50:25.577718 Py_Main(2, 0x7ffcbdb8faf8, 0x7ffcbdb8fb10, 0 <unfinished ...>
# [pid 28696] 08:50:25.578559 ioctl@SYS(0, 0x5401, 0x7ffcbdb8f860, 653) = 0 <0.000037>
# [pid 28696] 08:50:25.578649 brk@SYS(nil)         = 0x21aa000 <0.000019>
# [pid 28696] 08:50:25.578682 brk@SYS(0x21cb000)   = 0x21cb000 <0.000021>
# ...
# [pid 28735] 08:51:40.608641 rt_sigaction@SYS(2, 0x7ffeaa2e6870, 0x7ffeaa2e6910, 8)                                = 0 <0.000109>
# [pid 28735] 08:51:40.611613 sendto@SYS(3, 0x19a7fd8, 5, 0)                                                        = 5 <0.000445>
# [pid 28735] 08:51:40.612230 shutdown@SYS(3, 2, 0, 0)                                                              = 0 <0.000119>
# [pid 28735] 08:51:40.612451 close@SYS(3)                                                                          = 0 <0.000156>
# [pid 28735] 08:51:40.615726 close@SYS(7)                                                                          = 0 <0.000305>
# [pid 28735] 08:51:40.616610 <... Py_Main resumed> )                                                               = 0 <1.092079>
# [pid 28735] 08:51:40.616913 exit_group@SYS(0 <no return ...>



def CreateFlowsFromLtraceLog(verbose,logStream):
    # The output format of the command ltrace seems very similar to strace
    # so for the moment, no reason not to use it.
    return CreateFlowsFromGenericLinuxLog(verbose,logStream,"ltrace")

################################################################################
# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildSTraceCommand(extCommand,aPid):
    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    aCmd = ["strace", "-q", "-qq", "-f", "-tt", "-T", "-s", G_StringSize]

    if platform.linux_distribution()[2] == 'Santiago':
        aCmd += [ "-e", "trace=desc,ipc,process,network"]
    else:
        aCmd += [ "-y", "-yy", "-e", "trace=desc,ipc,process,network,memory"]

    if extCommand:
        # Run tracer process as a detached grandchild, not as parent of the tracee. This reduces the visible
        # effect of strace by keeping the tracee a direct child of the calling process.
        aCmd += [ "-D" ]
        aCmd += extCommand
    else:
        aCmd += [ "-p", aPid ]
    return aCmd

#
# 22:41:05.094710 rt_sigaction(SIGRTMIN, {0x7f18d70feb20, [], SA_RESTORER|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000008>
# 22:41:05.094841 rt_sigaction(SIGRT_1, {0x7f18d70febb0, [], SA_RESTORER|SA_RESTART|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000018>
# 22:41:05.094965 rt_sigprocmask(SIG_UNBLOCK, [RTMIN RT_1], NULL, 8) = 0 <0.000007>
# 22:41:05.095113 getrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0 <0.000008>
# 22:41:05.095350 statfs("/sys/fs/selinux", 0x7ffd5a97f9e0) = -1 ENOENT (No such file or directory) <0.000019>
#
# The command parameters and the parsing are specific to strace.
# It returns a data structure which is generic.

def LogSTraceFileStream(extCommand,aPid):
    aCmd = BuildSTraceCommand( extCommand, aPid )
    if extCommand:
        LogSource("Command "+" ".join(extCommand) )
    else:
        LogSource("Process %s\n"%aPid)
    return GenerateLinuxStreamFromCommand(aCmd, aPid)

def CreateFlowsFromLinuxSTraceLog(verbose,logStream):
    return CreateFlowsFromGenericLinuxLog(verbose,logStream,"strace")


################################################################################

# This is const
G_traceToTracer = {
    "cdb"    : ( LogWindowsFileStream, CreateFlowsFromWindowsLogger ),
    "strace" : ( LogSTraceFileStream , CreateFlowsFromLinuxSTraceLog ),
    "ltrace" : ( LogLTraceFileStream, CreateFlowsFromLtraceLog )
    }

################################################################################
# These global variables allow to better simulate the execution context
# when replaying a session.

# Read from a real process or from the log file name when replaying a session.
G_topProcessId = None

# Read from a real process or from the ini file when replaying a session.
G_CurrentDirectory = None

# The date where the test was run. Loaded from the ini file when replaying.
G_Today = None

G_Hostname = None

G_OSType = None

# When replaying a session, it is not worth getting information about processes
# because they do not exist anymore.
G_ReplayMode = False

################################################################################

def DefaultTracer(inputLogFile,tracer=None):
    if not tracer:
        if inputLogFile:
            # Maybe the pid is embedded in the log file.
            matchTrace = re.match(r".*\.([^\.]*)\.[0-9]+\.log", inputLogFile )
            if matchTrace:
                tracer = matchTrace.group(1)
            else:
                # The file format might be "xyzxyz.strace.log", "abcabc.ltrace.log", "123123.cdb.log"
                # depending on the tool which generated the log.
                matchTrace = re.match(r".*\.([^\.]*)\.log", inputLogFile )
                if not matchTrace:
                    raise Exception("Cannot read tracer from log file name:%s"%inputLogFile)
                tracer = matchTrace.group(1)
        else:
            if sys.platform.startswith("win32"):
                tracer = "cdb"
            elif sys.platform.startswith("linux"):
                # This could also be "ltrace", but "strace" is more usual.
                tracer = "strace"
            else:
                raise Exception("Unknown platform")
    LogSource("Tracer "+tracer)
    return tracer


def LoadIniFile(iniFilNam):
    mapKV = {}
    try:
        filOp =  open(iniFilNam)
        LogSource("Init "+iniFilNam)
    except IOError:
        return mapKV
    for linKV in filOp.readlines():
        clnKV = linKV.strip()
        if not clnKV: continue
        if clnKV[0] == ';': continue
        idxEq = clnKV.find('=')
        if idxEq < 0: continue
        prmKey = clnKV[:idxEq]
        prmVal = clnKV[idxEq+1:]
        mapKV[prmKey] = prmVal
    filOp.close()
    return mapKV

# This returns a stream with each line written by strace or ltrace.
def CreateEventLog(argsCmd, aPid, inputLogFile, tracer ):
    global G_topProcessId
    global G_CurrentDirectory
    global G_Today
    global G_Hostname
    global G_OSType
    global G_ReplayMode
    global G_SameMachine

    # A command or a pid or an input log file, only one possibility.
    if argsCmd != []:
        if aPid > 0 or inputLogFile:
            Usage(1,"When providing command, must not specify process id or input log file")
    elif aPid> 0 :
        if argsCmd != []:
            Usage(1,"When providing process id, must not specify command or input log file")
    elif inputLogFile:
        if argsCmd != []:
            Usage(1,"When providing input file, must not specify command or process id")
    else:
        Usage(1,"Must provide command, pid or input file")

    dateTodayRun = time.strftime("%Y-%m-%d")
    theHostNam = socket.gethostname()
    thePlatform = sys.platform

    currWrkDir = os.getcwd()
    if inputLogFile:
        logStream = open(inputLogFile)
        LogSource("File "+inputLogFile)
        LogSource("Logfile %s pid=%s" % (inputLogFile,aPid) )

        # There might be a context file with important information to reproduce the test.
        contextLogFile = os.path.splitext(inputLogFile)[0]+"."+"ini"
        mapKV = LoadIniFile(contextLogFile)

        # The main process pid might be embedded in the log file name,
        # but preferably stored in the ini file.
        G_topProcessId = int(mapKV.get("TopProcessId",aPid))

        G_CurrentDirectory = mapKV.get("CurrentDirectory",currWrkDir)
        G_Today            = mapKV.get("CurrentDate",dateTodayRun)
        G_Hostname         = mapKV.get("CurrentHostname",theHostNam)
        G_OSType           = mapKV.get("CurrentOSType",thePlatform)

        G_ReplayMode = True

        sys.stdout.write("G_topProcessId=%d\n"%G_topProcessId)
    else:
        try:
            funcTrace = G_traceToTracer[ tracer ][0]
        except KeyError:
            raise Exception("Unknown tracer:%s"%tracer)

        ( G_topProcessId, logStream ) = funcTrace(argsCmd,aPid)
        G_CurrentDirectory = currWrkDir
        G_Today = dateTodayRun
        G_Hostname = theHostNam
        G_OSType = thePlatform

        G_ReplayMode = False

    G_SameMachine = not G_ReplayMode or G_Hostname == socket.gethostname()


    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return logStream


# Global variables which must be reinitialised before a run.
def InitGlobals( withWarning ):
    global G_stackUnfinishedBatches
    G_stackUnfinishedBatches = UnfinishedBatches(withWarning)

    def InitObjectsCache():
        global G_mapCacheObjects
        G_mapCacheObjects = {}

        CreateObjectPath(CIM_ComputerSystem,socket.gethostname())
        CreateObjectPath(CIM_OperatingSystem)
        CreateObjectPath(CIM_NetworkAdapter,socket.gethostbyname(socket.gethostname()))

    InitObjectsCache()

    global G_mapFilDesToPathName
    G_mapFilDesToPathName = {
        "0" : "stdin",
        "1" : "stdout",
        "2" : "stderr"}

    # As read from the strace or ltrace calls to getenv()
    global G_EnvironmentVariables
    G_EnvironmentVariables = {}

    global G_cacheFileAccesses
    G_cacheFileAccesses = {}
        
# This receives a stream of lines, each of them is a function call,
# possibily unfinished/resumed/interrupted by a signal.
def CreateMapFlowFromStream( verbose, withWarning, logStream, tracer,outputFormat):
    # Here, we have an event log as a stream, which comes from a file (if testing),
    # the output of strace or anything else.

    InitGlobals(withWarning)

    mapFlows = {}

    # This step transforms the input log into a map of BatchFlow,
    # which have the same format whatever the platform is.
    try:
        funcCreator = G_traceToTracer[ tracer ][1]
    except KeyError:
        raise Exception("Unknown tracer:%s"%tracer)

    # This generator creates individual BatchLet objects on-the-fly.
    # At this stage, "resumed" calls are matched with the previously received "unfinished"
    # line for the same call.
    # Some calls, for some reason, might stay "unfinished": Though,
    # they are still needed to rebuild the processes tree.
    mapFlowsGenerator = funcCreator(verbose,logStream)

    # Maybe, some system calls are unfinished, i.e. the "resumed" part of the call
    # is never seen. They might be matched later.
    for oneBatch in mapFlowsGenerator:
        aCore = oneBatch.m_core


### NO: We must create immediately the derived objects so we can fill the caches in the right order.
### For example in the case where one file descriptor is created in a thread and used in another.
### In other words:
### - Loop on the incoming lines.
### - For each new pid ... or new burst of activity, create a coroutine:
###   This coroutine "is yielded" with new BatchCore objects.

        aPid = aCore.m_pid
        try:
            btchFlow = mapFlows[ aPid ]
        except KeyError:
            # This is the first system call of this process.
            btchFlow = BatchFlow()
            mapFlows[ aPid ] = btchFlow

        if False:
            btchFlow.AddBatch( oneBatch )
        else:
            btchFlow.SendBatch( oneBatch )
    for aPid in sorted(list(mapFlows.keys()),reverse=True):
        btchTree = mapFlows[aPid]
        if verbose > 0: sys.stdout.write("\n------------------ PID=%d\n"%aPid)
        btchTree.FactorizeOneFlow(verbose,withWarning,outputFormat)
        

    return mapFlows

################################################################################

# All possible summaries. Data created for the summaries are also needed
# to generate a docker file. So, summaries are calculated if Dockerfile is asked.
fullMapParamsSummary = ["CIM_ComputerSystem","CIM_OperatingSystem","CIM_NetworkAdapter","CIM_Process","CIM_DataFile"]

def FromStreamToFlow(
        verbose, withWarning, logStream, tracer, outputFormat,
        baseOutName, mapParamsSummary, summaryFormat, withDockerfile):
    if not baseOutName:
        baseOutName = "results"
    if summaryFormat:
        outputSummaryFile = baseOutName + ".summary." + summaryFormat.lower()
    else:
        outputSummaryFile = None

    mapFlows = CreateMapFlowFromStream( verbose, withWarning, logStream, tracer, outputFormat)

    G_stackUnfinishedBatches.PrintUnfinished(sys.stdout)

    if baseOutName and outputFormat:
        outFile = baseOutName + "." + outputFormat.lower()
        sys.stdout.write("Creating flow file:%s\n" % outFile)
        outFd = open(outFile, "w")
        batchConstructor = BatchDumpersDictionary[outputFormat]
        batchDump = batchConstructor(outFd)
        batchDump.DocumentStart()
        for aPid in sorted(list(mapFlows.keys()),reverse=True):
            btchTree = mapFlows[aPid]
            btchTree.DumpFlowConstructor(batchDump, "================== PID=%d"%aPid)
        batchDump.DocumentEnd()
        outFd.close()

        if verbose: sys.stdout.write("\n")

    # Generating a docker file needs some data calculated withthe summaries.
    if withDockerfile:
        mapParamsSummary = fullMapParamsSummary

    GenerateSummary(mapParamsSummary, summaryFormat, outputSummaryFile)
    
    if withDockerfile:
        if outFile:
            baseOutName, filOutExt = os.path.splitext(outFile)
        elif outputSummaryFile:
            baseOutName, filOutExt = os.path.splitext(outputSummaryFile)
        else:
            baseOutName = "docker"
        dockerDirName = baseOutName + ".docker"
        if os.path.exists(dockerDirName):
            shutil.rmtree(dockerDirName)
        os.makedirs(dockerDirName)

        dockerFilename = dockerDirName + "/Dockerfile"
        GenerateDockerFile(dockerFilename)

    return outputSummaryFile

# Function called for unit tests by unittest.py
def UnitTest(
        inputLogFile, tracer, topPid, baseOutName, outputFormat, verbose, mapParamsSummary,
        summaryFormat, withWarning, withDockerfile, updateServer):
    global G_UpdateServer
    assert isinstance(topPid, int)
    logStream = CreateEventLog([], topPid, inputLogFile, tracer )
    G_UpdateServer = updateServer

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.

    outputSummaryFile = FromStreamToFlow(
        verbose, withWarning, logStream, tracer, outputFormat, baseOutName,
        mapParamsSummary, summaryFormat, withDockerfile)
    return outputSummaryFile

if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvws:Dp:f:F:r:i:l:t:S:",
                ["help","verbose","warning","summary","summary-format",
                 "docker","pid","format","repetition","input",
                 "log","tracer","server"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = 0
    withWarning = 0

    # By default, generates all summaries. The filter syntax is based on CIM object pathes:
    # -s 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
    # -s "CIM+_DataFile:Category=['Others','Shared libraries']"
    #
    # At the moment, the summary generates only two sorts of objects: CIM_Process and CIM_DataFile.
    # mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"]
    mapParamsSummary = fullMapParamsSummary

    withDockerfile = None

    aPid = -1
    outputFormat = "TXT" # Default output format of the generated files.
    szWindow = 0
    inputLogFile = None
    summaryFormat = None
    outputLogFilePrefix = None
    tracer = None

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose += 1
        elif anOpt in ("-w", "--warning"):
            withWarning += 1
        elif anOpt in ("-s", "--summary"):
            mapParamsSummary = mapParamsSummary + [ aVal ] if aVal else []
        elif anOpt in ("-D", "--dockerfile"):
            withDockerfile = True
        elif anOpt in ("-p", "--pid"):
            aPid = aVal
        elif anOpt in ("-f", "--format"):
            outputFormat = aVal.upper()
        elif anOpt in ("-F", "--summary_format"):
            summaryFormat = aVal.upper()
        elif anOpt in ("-w", "--window"):
            szWindow = int(aVal)
            raise Exception("Sliding window not implemented yet")
        elif anOpt in ("-i", "--input"):
            inputLogFile = aVal
        elif anOpt in ("-l", "--log"):
            outputLogFilePrefix = aVal
        elif anOpt in ("-t", "--tracer"):
            tracer = aVal
        elif anOpt in ("-S", "--server"):
            G_UpdateServer = aVal
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"


    tracer = DefaultTracer( inputLogFile, tracer )
    logStream = CreateEventLog(argsCmd, aPid, inputLogFile, tracer )

    if outputLogFilePrefix:
        fullPrefixNoExt = "%s.%s.%s." % ( outputLogFilePrefix, tracer, G_topProcessId )

        # tee: This just needs to reimplement "readline()"
        class TeeStream:
            def __init__(self,logStrm):
                self.m_logStrm = logStrm
                logFilNam = fullPrefixNoExt + "log"
                self.m_outFd = open( logFilNam, "w" )
                print("Creating log file:%s" % logFilNam )

            def readline(self):
                # sys.stdout.write("xxx\n" )
                aLin = self.m_logStrm.readline()
                # sys.stdout.write("tee=%s" % aLin)
                self.m_outFd.write(aLin)
                return aLin

        logStream = TeeStream(logStream)

        #outFilExt = outputFormat.lower() # "txt", "xml" etc...
        #outFilNam = fullPrefixNoExt + outFilExt

        # If not replaying, saves all parameters in an ini file.
        if not G_ReplayMode:
            iniFilNam = fullPrefixNoExt + "ini"
            iniFd = open(iniFilNam,"w")

            # At this stage, we know what is the top process id,
            # because the command is created, or the process attached.
            iniFd.write('TopProcessId=%s\n' % G_topProcessId )

            iniFd.write('CurrentDirectory=%s\n' % os.getcwd() )
            # Necessary because ltrace and strace do not write the date.
            # Done before testing in case the test stops next day.
            iniFd.write('CurrentDate=%s\n' % G_Today)
            iniFd.write('CurrentHostname=%s\n' % socket.gethostname())
            iniFd.write('CurrentOSType=%s\n' % sys.platform)
            iniFd.close()
    #else:
    #    outFilNam = None

    def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        global G_Interrupt
        G_Interrupt = True

    # When waiting for a process, interrupt with control-C.
    if aPid > 0:
        signal.signal(signal.SIGINT, signal_handler)
        print('Press Ctrl+C to exit cleanly')

    # In normal usage, the summary output format is the same as the output format for calls.
    FromStreamToFlow(verbose, withWarning, logStream, tracer,outputFormat, fullPrefixNoExt, mapParamsSummary, summaryFormat, withDockerfile )

################################################################################
# The End.
################################################################################
