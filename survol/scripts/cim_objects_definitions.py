import os
import re
import sys
import json
import platform
import datetime
import socket
import shutil
import threading
import time

try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

try:
    # Optional: To add more information to processes etc...
    import psutil
except ImportError:
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

################################################################################

# Buffers transferred with read() and write() are parsed to detect information
# about the running applications. There can be several types of parsers,
# indexed by a descriptive key.
BufferScanners = {}

try:
    sys.path.append("../..")

    # This creates the SQL queries scanner, it needs Survol code.
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
G_FilesToPackagesCache = None

G_SameMachine = None

G_ReplayMode = None

# This is a dictionary (indexed by processes) of dictionaries (indexed by files).
# It containes files accesses, which are object representing what happens
# to a file between its opening and closing by a process.
G_cacheFileAccesses = {}

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
        except Exception as exc:
            # Example: '[pid  5602] 19:59:20.590740 <... read resumed> "... end of read() content"..., 32768) = 4096 <0.037642>'
            sys.stdout.write("Cannot parse:%s szBuffer=%s: %s\n" % (aBuffer, szBuffer, exc))
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
        assert G_cacheFileAccesses is not None

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

# When replaying a session, it is not worth getting information about processes
# because they do not exist anymore.
G_ReplayMode = False

# The date where the test was run. Loaded from the ini file when replaying.
G_Today = None

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

    # Today's date can change so we can reproduce a run.TimeStampToStr
    if timStamp:
        return G_Today + " " + timStamp
    else:
        return G_Today + " 00:00:00.000000"

################################################################################

sys.path.append("../..")
# Import this now, and not in the destructor, to avoid the error:
# "sys.meta_path must be a list of import hooks"
# This module is needed for storing the generated data into a RDF file.
try:
    from survol import lib_event
except ImportError:
    lib_event = None

# This objects groups triples to send to the HTTP server,
# and periodically wakes up to send them.
# But if the server name is a file, the RDF content is instead stored to this
 # file by the object destructor.
class HttpTriplesClient(object):
    def __init__(self):
        self.m_listTriples = []
        # Tests if this a output RDF file, or rather None or the URL of a Survol agent.
        self.m_server_is_file = G_UpdateServer and not(
                G_UpdateServer.lower().startswith("http:")
                or G_UpdateServer.lower().startswith("https:") )
        if self.m_server_is_file:
            print("G_UpdateServer=", G_UpdateServer, " IS FILE")
            return
        elif G_UpdateServer:
            self.m_sharedLock = threading.Lock()
            aThrd = threading.Thread(target = self.run)
            # If leaving too early, some data might be lost.
            aThrd.daemon = True
            aThrd.start()
            self.m_valid = True

    def Shutdown(self):
        print("HttpTriplesClient.Shutdown")
        if self.m_server_is_file:
            lib_event.json_triples_to_rdf(self.m_listTriples, G_UpdateServer)
            print("Stored RDF content to", G_UpdateServer)
        elif G_UpdateServer:
            print("TODO: Flush data to Survol agent")

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
        if self.m_server_is_file:
            # Just append the triple, no need to synchronise.
            self.m_listTriples.append(jsonTriple)
        elif self.m_valid and G_UpdateServer:
            self.m_sharedLock.acquire()
            self.m_listTriples.append(jsonTriple)
            self.m_sharedLock.release()

# This is the Survol server which is notified of all updates
# of CIM objects. These updates can then be displayed in Survol Web clients.
# It must be a plain Web server to be hosted by Apache or IIS.
G_UpdateServer = None

################################################################################

# attr=AccessTime attrVal=1518262584.92 <type 'float'>
def TimeT_to_DateTime(stTimeT):
    # Or utcfromtimestamp
    return datetime.datetime.strftime( datetime.datetime.fromtimestamp(stTimeT), "%H:%M:%S:%f")

################################################################################

def IsCIM(attr,attrVal):
    return not callable(attrVal) and not attr.startswith("__") and not attr.startswith("m_")

def IsTimeStamp(attr,attrVal):
    return attr.find("Date") > 0 or attr.find("Time") > 0



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

# Read from a real process or from the ini file when replaying a session.
G_CurrentDirectory = None


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
class CIM_ComputerSystem(CIM_XmlMarshaller, object):
    def __init__(self, hostname):
        super(CIM_ComputerSystem, self).__init__()
        self.Name = hostname.lower()  # This is a convention.

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
class CIM_OperatingSystem(CIM_XmlMarshaller, object):
    def __init__(self):
        super(CIM_OperatingSystem, self).__init__()

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
class CIM_NetworkAdapter(CIM_XmlMarshaller, object):
    def __init__(self, address):
        super(CIM_NetworkAdapter, self).__init__()
        self.Name = address
        self.PermanentAddress = address

    m_Ontology = ['Name']


# class CIM_Process : CIM_LogicalElement
# {
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
# };
class CIM_Process(CIM_XmlMarshaller, object):
    def __init__(self, procId):
        super(CIM_Process, self).__init__()

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
                                envVal = onePair[ixEq + 1:]
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
                execFilObj = CreateObjectPath(CIM_DataFile, execFilNam)
                self.SetExecutable(execFilObj)
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
                firstProcObj = mapProcs[firstProcId]
                if firstProcId != ('CIM_Process.Handle="%s"' % firstProcObj.Handle):
                    raise Exception("Inconsistent procid:%s != %s" % (firstProcId, firstProcObj.Handle))

                if firstProcObj.Handle == procId:
                    raise Exception("Duplicate procid:%s" % procId)
                self.SetParentProcess(firstProcObj)
        except KeyError:
            # This is the first process.
            pass

    m_Ontology = ['Handle']

    @classmethod
    def DisplaySummary(theClass, fdSummaryFile, cimKeyValuePairs):
        fdSummaryFile.write("Processes:\n")
        print("keys=", G_mapCacheObjects.keys())
        for objPath, objInstance in sorted(G_mapCacheObjects[CIM_Process.__name__].items()):
            # sys.stdout.write("Path=%s\n"%objPath)
            objInstance.Summarize(fdSummaryFile)
        fdSummaryFile.write("\n")

    m_AttrsPriorities = ["Handle", "Name", "CommandLine", "CreationDate", "TerminationDate", "Priority"]

    def XMLOneLevelSummary(self, strm, margin="    "):
        self.m_isVisited = True
        strm.write("%s<CIM_Process Handle='%s'>\n" % (margin, self.Handle))

        subMargin = margin + "    "

        self.PlainToXML(strm, subMargin)

        FileAccess.VectorToXML(strm, self.m_ProcessFileAccesses, subMargin, False)

        for objInstance in self.m_subProcesses:
            objInstance.XMLOneLevelSummary(strm, subMargin)
        strm.write("%s</CIM_Process>\n" % (margin))

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
        for objPath, objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            for oneSub in objInstance.m_subProcesses:
                setSubProcs.add(oneSub)

        lstTopLvl = []
        for objPath, objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            if objInstance not in setSubProcs:
                lstTopLvl.append(objInstance)
        return lstTopLvl

    # When parsing the last system call, it sets the termination date for all processes.
    @staticmethod
    def GlobalTerminationDate(timeEnd):
        for objPath, objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            if not objInstance.TerminationDate:
                objInstance.TerminationDate = timeEnd

    @classmethod
    def XMLSummary(theClass, fdSummaryFile, cimKeyValuePairs):
        # Find unvisited processes. It does not start from G_top_ProcessId
        # because maybe it contains several trees, or subtrees were missed etc...
        for objPath, objInstance in sorted(G_mapCacheObjects[CIM_Process.__name__].items()):
            try:
                objInstance.m_isVisited
                continue
            except AttributeError:
                pass

            topObjProc = CIM_Process.TopProcessFromProc(objInstance)

            topObjProc.XMLOneLevelSummary(fdSummaryFile)

    # In text mode, with no special formatting.
    def Summarize(self, strm):
        strm.write("Process id:%s\n" % self.Handle)
        try:
            if self.Executable:
                strm.write("    Executable:%s\n" % self.Executable)
        except AttributeError:
            pass
        if self.CreationDate:
            strStart = TimeStampToStr(self.CreationDate)
            strm.write("    Start time:%s\n" % strStart)
        if self.TerminationDate:
            strEnd = TimeStampToStr(self.TerminationDate)
            strm.write("    End time:%s\n" % strEnd)
        if self.m_parentProcess:
            strm.write("    Parent:%s\n" % self.m_parentProcess.Handle)

    def SetParentProcess(self, objCIM_Process):
        # sys.stdout.write("SetParentProcess proc=%s parent=%s\n" % ( self.Handle, objCIM_Process.Handle ) )
        if int(self.Handle) == int(objCIM_Process.Handle):
            raise Exception("Self-parent")
        self.m_parentProcess = objCIM_Process
        objCIM_Process.m_subProcesses.add(self)

    def AddParentProcess(self, timeStamp, objCIM_Process):
        self.SetParentProcess(objCIM_Process)
        self.CreationDate = timeStamp

    def WaitProcessEnd(self, timeStamp, objCIM_Process):
        # sys.stdout.write("WaitProcessEnd: %s linking to %s\n" % (self.Handle,objCIM_Process.Handle))
        self.TerminationDate = timeStamp
        if not self.m_parentProcess:
            self.SetParentProcess(objCIM_Process)
            # sys.stdout.write("WaitProcessEnd: %s not linked to %s\n" % (self.Handle,objCIM_Process.Handle))
        elif self.m_parentProcess != objCIM_Process:
            # sys.stdout.write("WaitProcessEnd: %s not %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass
        else:
            # sys.stdout.write("WaitProcessEnd: %s already linked to %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass

    def SetExecutable(self, objCIM_DataFile):
        assert (isinstance(objCIM_DataFile, CIM_DataFile))
        self.Executable = objCIM_DataFile.Name
        self.m_ExecutableObject = objCIM_DataFile

    def SetCommandLine(self, lstCmdLine):
        # TypeError: sequence item 7: expected string, dict found
        if lstCmdLine:
            self.CommandLine = " ".join([str(elt) for elt in lstCmdLine])
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
            commandList = [self.Executable]
        except AttributeError:
            commandList = []
        return commandList

    def SetThread(self):
        self.IsThread = True

    # Some system calls are relative to the current directory.
    # Therefore, this traces current dir changes due to system calls.
    def SetProcessCurrentDir(self, currDirObject):
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
        filAcc = FileAccess.LookupFileAccess(self, objCIM_DataFile)
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
class CIM_DataFile(CIM_XmlMarshaller, object):
    def __init__(self, pathName):
        super(CIM_DataFile, self).__init__()

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
            self.SetAddrPort(mtchSock.group(1))
        else:
            # 'TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]'
            mtchSock = re.match(r"TCPv6:\[.*->(.*)\]", pathName)
            if mtchSock:
                self.SetAddrPort(mtchSock.group(1))

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
        mapOfFilesMap = {rgxTuple[0]: {} for rgxTuple in G_lstFilters}

        # objPath = 'CIM_DataFile.Name="/usr/lib64/libcap.so.2.24"'
        for objPath, objInstance in mapFiles:
            mapOfFilesMap[objInstance.Category][objPath] = objInstance
        return mapOfFilesMap

    @classmethod
    def DisplaySummary(theClass, fdSummaryFile, cimKeyValuePairs):
        fdSummaryFile.write("Files:\n")
        mapOfFilesMap = CIM_DataFile.SplitFilesByCategory()

        try:
            filterCats = cimKeyValuePairs["Category"]
        except KeyError:
            filterCats = None

        for categoryFiles, mapFilesSub in sorted(mapOfFilesMap.items()):
            fdSummaryFile.write("\n** %s\n" % categoryFiles)
            if filterCats and (not categoryFiles in filterCats): continue
            for objPath, objInstance in sorted(mapFilesSub.items()):
                # sys.stdout.write("Path=%s\n"%objPath)
                objInstance.Summarize(fdSummaryFile)
        fdSummaryFile.write("\n")

    m_AttrsPriorities = ["Name", "Category", "SocketAddress"]

    def XMLDisplay(self, strm):
        margin = "        "
        strm.write("%s<CIM_DataFile Name='%s'>\n" % (margin, self.Name))

        subMargin = margin + "    "

        self.PlainToXML(strm, subMargin)

        FileAccess.VectorToXML(strm, self.m_DataFileFileAccesses, subMargin, True)

        strm.write("%s</CIM_DataFile>\n" % (margin))

    @staticmethod
    def XMLCategorySummary(fdSummaryFile, mapFilesSub):
        for objPath, objInstance in sorted(mapFilesSub.items()):
            # sys.stdout.write("Path=%s\n"%objPath)
            objInstance.XMLDisplay(fdSummaryFile)

    @classmethod
    def XMLSummary(theClass, fdSummaryFile, cimKeyValuePairs):
        """Top-level informations are categories of CIM_DataFile which are not technical
        but the regex-based filtering."""
        mapOfFilesMap = CIM_DataFile.SplitFilesByCategory()

        try:
            filterCats = cimKeyValuePairs["Category"]
        except KeyError:
            filterCats = None

        for categoryFiles, mapFilesSub in sorted(mapOfFilesMap.items()):
            if len(mapFilesSub) == 0:
                # No need to write a category name if it is empty.
                continue

            fdSummaryFile.write("    <FilesCategory category='%s'>\n" % categoryFiles)
            if filterCats and (not categoryFiles in filterCats): continue
            CIM_DataFile.XMLCategorySummary(fdSummaryFile, mapFilesSub)
            fdSummaryFile.write("    </FilesCategory>\n")

    def Summarize(self, strm):
        try:
            # By default, this attribute is not set.
            if self.IsExecuted:
                return
        except AttributeError:
            pass
        strm.write("Path:%s\n" % self.Name)

        for filAcc in self.m_DataFileFileAccesses:

            if filAcc.OpenTime:
                strOpen = TimeStampToStr(filAcc.OpenTime)
                strm.write("  Open:%s\n" % strOpen)

                try:
                    strm.write("  Open times:%d\n" % filAcc.NumOpen)
                except AttributeError:
                    pass

            if filAcc.CloseTime:
                strClose = TimeStampToStr(filAcc.CloseTime)
                strm.write("  Close:%s\n" % strClose)

        # Only if this is a socket.
        # The original socket parameters might have been passed as a dict like:
        # "connect(6<UNIX:[587259]>, {sa_family=AF_LOCAL, sun_path="/var/run/nscd/socket"}, 110)"
        # But it might have been truncated like:
        # "['st_mode=S_IFREG|0644', 'st_size=121043', '...']"
        # So we are only sure that it is an array.
        try:
            for saKeyValue in self.SocketAddress:
                strm.write("    %s\n" % saKeyValue)
        except AttributeError:
            pass

    def SetIsExecuted(self):
        self.IsExecuted = True

    # The input could be IPV4 or IPV6:
    # '82.45.12.63:63708]'
    # '::ffff:82.45.12.63:63703]'
    def SetAddrPort(self, pathIP):
        ixEq = pathIP.rfind(":")
        if ixEq < 0:
            self.Destination = pathIP
        else:
            self.Port = pathIP[ixEq + 1:]
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
        for objPath, objInstance in mapFiles:
            try:
                setPorts.add(objInstance.Port)
            except AttributeError:
                pass
        return setPorts

    m_nonFilePrefixes = ["UNIX:", "TCP:", "TCPv6:", "NETLINK:", "pipe:", "UDP:", "UDPv6:", ]

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

################################################################################

# os.path.abspath removes things like . and .. from the path
# giving a full path from the root of the directory tree to the named file (or symlink)
def ToAbsPath( dirPath, filNam ):
    # This does not apply to pseudo-files such as: "pipe:", "TCPv6:" etc...
    if re.match("^[0-9a-zA-Z_]+:", filNam):
        return filNam

    if filNam in ["stdout", "stdin", "stderr"]:
        return filNam

    join_path = os.path.join(dirPath, filNam)
    norm_path = os.path.realpath(join_path)
    return norm_path

################################################################################

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

################################################################################

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
            fdDockerFile.write("ENV %s %s\n" % (envNam, envVal))

        fdDockerFile.write("\n")

    def WriteProcessTree():
        """Only for documentation purpose"""

        def WriteOneProcessSubTree(objProc, depth):
            commandLine = objProc.GetCommandLine()
            if not commandLine:
                commandLine = "????"
            fdDockerFile.write("# %s -> %s : %s %s\n" % (
            TimeStampToStr(objProc.CreationDate), TimeStampToStr(objProc.TerminationDate), "    " * depth, commandLine))

            for subProc in sorted(objProc.m_subProcesses, key=lambda x: x.Handle):
                WriteOneProcessSubTree(subProc, depth + 1)

        fdDockerFile.write("# Processes tree\n")

        procsTopLevel = CIM_Process.GetTopProcesses()
        for oneProc in sorted(procsTopLevel, key=lambda x: x.Handle):
            WriteOneProcessSubTree(oneProc, 1)
        fdDockerFile.write("\n")

    currNow = datetime.datetime.now()
    currDatTim = currNow.strftime("%Y-%m-%d %H:%M:%S:%f")
    fdDockerFile.write("# Dockerfile generated %s\n" % currDatTim)

    dockerDirectory = os.path.dirname(dockerFilename)
    fdDockerFile.write("# Directory %s\n" % dockerDirectory)
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
        fdDockerFile.write("WORKDIR %s\n" % currDir)

        commandList = oneProc.GetCommandList()
        if commandList:
            # If the string length read by ltrace or strace is too short,
            # some arguments are truncated: 'CMD ["python TestProgs/big_mysql_..."]'

            # There should be one CMD command only !
            strCmd = ",".join('"%s"' % wrd for wrd in commandList)

            fdDockerFile.write("CMD [ %s ]\n" % strCmd)
    fdDockerFile.write("\n")

    portsList = CIM_DataFile.GetExposedPorts()
    if portsList:
        fdDockerFile.write("# Port numbers:\n")
        for onePort in portsList:
            try:
                txtPort = socket.getservbyport(int(onePort))
                fdDockerFile.write("# Service: %s\n" % txtPort)
            except:
                fdDockerFile.write("# Unknown service number: %s\n" % onePort)
            fdDockerFile.write("EXPOSE %s\n" % onePort)
        fdDockerFile.write("\n")

    WriteEnvironVar()

    WriteProcessTree()

    # More examples here:
    # https://github.com/kstaken/dockerfile-examples/blob/master/couchdb/Dockerfile

    fdDockerFile.close()
    return

# Environment variables actually access by processes.
# Used to generate a Dockerfile.
# As read from the strace or ltrace calls to getenv()
G_EnvironmentVariables = None

def InitGlobalObjects():
    global G_mapCacheObjects
    global G_httpClient
    global G_EnvironmentVariables
    G_mapCacheObjects = {}

    # This object is used to send triples to a Survol server.
    # It is also used to store the triples in a RDF file, which is created by the destructor.
    G_httpClient = HttpTriplesClient()

    # As read from the strace or ltrace calls to getenv()
    G_EnvironmentVariables = {}

    CreateObjectPath(CIM_ComputerSystem, socket.gethostname())
    CreateObjectPath(CIM_OperatingSystem)
    CreateObjectPath(CIM_NetworkAdapter, socket.gethostbyname(socket.gethostname()))

def ExitGlobalObjects():
    # It is also used to store the triples in a RDF file, which is created by the destructor.
    global G_httpClient
    # Flushes the data to a file or possibly a Survol agent.
    G_httpClient.Shutdown()


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
    def InstallPipModule(fdDockerFile, namePyModule):
        fdDockerFile.write("RUN pip --disable-pip-version-check install %s\n" % namePyModule)

    def InstallLinuxPackage(fdDockerFile, packageName):

        # packageName = "mariadb-libs-10.1.30-2.fc26.x86_64"
        # RUN yum install mariadb-libs
        if packageName in InstallLinuxPackage.InstalledPackages:
            pckShort = InstallLinuxPackage.InstalledPackages[packageName]
            fdDockerFile.write("# Already installed %s -> %s\n" % (pckShort, packageName))
            return

        # TODO: Maybe there are several versions of the same package.
        mtch = re.search(r'(.*)-(.*)-(.*?)\.(.*)', packageName)
        if mtch:
            (pckShort, version, release, platform) = mtch.groups()
        else:
            pckShort = packageName

        InstallLinuxPackage.InstalledPackages[packageName] = pckShort

        # Step 4/7 : RUN yum -y install coreutils # coreutils-8.27-5.fc26.x86_64
        # Problem: problem with installed package coreutils-single-8.29-5.fc28.x86_64
        # - package coreutils-8.29-5.fc28.x86_64 conflicts with coreutils-single provided by coreutils-single-8.29-5.fc28.x86_64
        # (try to add '--allowerasing' to command line to replace conflicting packages or '--skip-broken' to skip uninstallable packages)

        # For the moment, this is simpler.
        if pckShort in ['coreutils']:
            fdDockerFile.write("# Potential conflict with %s , %s\n" % (pckShort, packageName))
        else:
            fdDockerFile.write("RUN yum -y install %s # %s\n" % (pckShort, packageName))

    # Each package is installed only once.
    InstallLinuxPackage.InstalledPackages = dict()

    # FIXME: We could copy an entire directory tree. When ?
    def AddToDockerDir(pathName, filComment=0):
        # Maybe the input file does not exist.
        if not os.path.exists(pathName):
            fdDockerFile.write("# Origin file does not exist:%s\n" % (pathName))
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
            sys.stdout.write("Failed copy %s to %s\n" % (pathName, dstPath))
            # Maybe the file is not there because this is in replay mode,
            # rerunning a session form the log file. This is not a problem.
            fdDockerFile.write("# Cannot add non-existent file:%s\n" % (pathName))
            return

        if filComment:
            fdDockerFile.write("# %s\n" % (filComment))

        fdDockerFile.write("ADD %s %s\n" % (pathName, pathName))

    # Code dependencies and data files dependencies are different.

    # All versions mixed together which is realistic most of times.
    class Dependency:
        def __init__(self):
            self.m_accessedCodeFiles = set()

        def AddDep(self, pathName):
            self.m_accessedCodeFiles.add(pathName)

    class DependencyPython(Dependency, object):
        DependencyName = "Python scripts"

        def __init__(self):
            super(DependencyPython, self).__init__()

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

        def GenerateDockerDependencies(self, fdDockerFile):
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

                    if (ixPack >= 0) and (ixPack < len(splitFil) - 1):
                        pckNam = splitFil[ixPack + 1]
                        if not pckNam.endswith(".py") and not pckNam.endswith(".pyc"):
                            # filNam = 'abrt_exception_handler.py'
                            packagesToInstall.add(splitFil[ixPack + 1])
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
                InstallLinuxPackage(fdDockerFile, "python")
            for onePckgNam in sorted(packagesToInstall):
                # TODO: Do not duplicate Python modules installation.
                InstallPipModule(fdDockerFile, onePckgNam)

    class DependencyPerl(Dependency, object):
        DependencyName = "Perl scripts"

        def __init__(self):
            super(DependencyPerl, self).__init__()

        @staticmethod
        def IsDepType(objInstance):
            try:
                return objInstance.Executable.find("/perl") >= 0
            except AttributeError:
                # We do not know the executable, or it is a thread.
                return False

        @staticmethod
        def IsCode(objDataFile):
            return objDataFile.Name.endswith(".pl")

        def GenerateDockerDependencies(self, fdDockerFile):
            for objDataFile in self.m_accessedCodeFiles:
                filNam = objDataFile.Name
                fdDockerFile.write("RUN cpanm %s\n" % filNam)
            pass

    class DependencyBinary(Dependency, object):
        DependencyName = "Binary programs"

        def __init__(self):
            super(DependencyBinary, self).__init__()

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
            if basNam in ["ld.so.cache", "ld.so.preload"]:
                return True

            # Eliminates the extension and the version.
            noExt = basNam[: basNam.find(".")]
            noExt = noExt[: noExt.find("-")]
            if noExt in ["libdl", "libc", "libacl", "libm", "libutil", "libpthread"]:
                return True
            return False

        def GenerateDockerDependencies(self, fdDockerFile):
            # __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
            #    return objInstance.Executable.find("/python") >= 0 or objInstance.Executable.startswith("python")

            lstAccessedPackages, unpackagedAccessedCodeFiles = G_FilesToPackagesCache.GetPackagesList(
                self.m_accessedCodeFiles)

            fdDockerFile.write("# Package installations:\n")
            for namPackage in sorted(lstAccessedPackages):
                InstallLinuxPackage(fdDockerFile, namPackage)
            fdDockerFile.write("\n")

            fdDockerFile.write("# Non-packaged executable files copies:\n")
            sortAccessedCodeFiles = sorted(unpackagedAccessedCodeFiles, key=lambda x: x.Name)
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

    for objPath, objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
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
        InstallLinuxPackage(fdDockerFile, anExec)
    fdDockerFile.write("\n")

    # This must be done after the binaries are installed: For example installing Perl packages
    # with CPAN needs to install Perl.
    fdDockerFile.write("################################# Dependencies by program type\n")
    for oneDep in setUsefulDependencies:
        fdDockerFile.write("# Dependencies: %s\n" % oneDep.DependencyName)
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
            InstallPipModule(fdDockerFile, onePyModu)
        fdDockerFile.write("\n")

    fdDockerFile.write("# Data packages:\n")
    # TODO: Many of them are probably already installed.
    for anExec in sorted(lstPackagesData):
        InstallLinuxPackage(fdDockerFile, anExec)
    fdDockerFile.write("\n")

    if unknownDataFiles:
        fdDockerFile.write("# Data files:\n")
        # Sorted by alphabetical order.
        # It would be better to sort it after filtering.
        sortedDatFils = sorted(unknownDataFiles, key=lambda x: x.Name)
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
            if filNam in ["-1", "stdin", "stdout", "stderr", "."]:
                continue

            # Primitive tests so that directories are not copied.
            if filNam.endswith("/.") or filNam.endswith("/"):
                continue

            AddToDockerDir(filNam, datFil.Category)
    fdDockerFile.write("\n")

################################################################################

