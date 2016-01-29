# Windows Event Log Viewer
# FB - 201012116
import win32evtlog # requires pywin32 pre-installed
import time

server = 'localhost' # name of the target computer to get event logs
logtype = 'System' # 'Application' # 'Security'
hand = win32evtlog.OpenEventLog(server,logtype)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
total = win32evtlog.GetNumberOfEventLogRecords(hand)


filter = [
	"Multimedia Class Scheduler",
	"Windows Modules Installer",
	"SMS Task Sequence Agent",
	"WMI Performance Adapter",
	"Windows Installer",
	"Application Experience",
	"Windows Error Reporting Service",
	"Background Intelligent Transfer Service",
	"Google Update Service (gupdate)",
	"Google Update Service (gupdatem)",
	"Google Software Updater",
	"Volume Shadow Copy",
	"Microsoft Software Shadow Copy Provider",
	"WinHTTP Web Proxy Auto-Discovery Service",
	"Telephony",
	"Software Protection",
	"Office Software Protection Platform",
	"Diagnostic System Host",
	"Windows Backup",
	"Tablet PC Input Service",
	"SPP Notification Service",
	"Windows Search",
	"Microsoft .NET Framework NGEN v4.0.30319_X86"
	"Windows Font Cache service",
	"CNG Key Isolation",
	]

badsrc = [
	"SCardSvr",
	"Microsoft-Windows-Winlogon",
	"Microsoft-Windows-GroupPolicy",
	"Service Control Manager",
	"Microsoft-Windows-Kernel-Power",
	"Microsoft-Windows-Kernel-Processor-Power",
	"Microsoft-Windows-UserPnp",
	"Microsoft-Windows-FilterManager",
	"Microsoft-Windows-Kernel-General",
	"Microsoft-Windows-WindowsUpdateClient",
	"e1cexpress",
	"MEIx64",
	"EventLog",
	"LsaSrv",
	"Application Popup",
	"Microsoft-Windows-Dhcp-Client",
	"Microsoft-Windows-DHCPv6-Client",
	"Microsoft-Windows-Diagnostics-Networking",
	"USER32",
	"HTTP",
	"NETLOGON",
	"srv",
	"TermService"
	]

# Other sources:
#Event Category:0
#Time Generated:2015-01-28 11:11:07
#Source Name:Application Popup
#Event ID:1073741850
#Event Type:4
#WestTest.exe - Entry Point Not Found
#The procedure entry point for_finalize could not be located in the dynamic link library libifcoremd.dll.
#
#Event Category:0
#Time Generated:2015-01-28 10:49:26
#Source Name:Application Popup
#Event ID:1073741850
#Event Type:4
#WestTest.exe - System Error
#The program can't start because libifcoremd.dll is missing from your computer. Try reinstalling the program to fix this problem.
#
#Event Category:1
#Time Generated:2015-01-24 22:09:11
#Source Name:Microsoft-Windows-WindowsUpdateClient
#Event ID:19
#Event Type:4
#Update for Microsoft Office 2013 (KB2899501) 32-Bit Edition
#{E8AFCC63-12E7-4948-B2C4-EF74DF3146D0}
#200
#

while True:
	for event in  win32evtlog.ReadEventLog(hand, flags,0):
		data = event.StringInserts
		try:
			if data[0] in filter:
				continue
		except TypeError:
			continue

		if event.SourceName in badsrc:
			continue

		print('Event Category:%d' % event.EventCategory)
		print('Time Generated:'+ str(event.TimeGenerated))
		print('Source Name:'+ event.SourceName)
		print('Event ID:%d' %event.EventID)
		print('Event Type:%d'% event.EventType)

		if data:
			# ('Event Data:')
			for msg in data:
				try:
					print(msg)
				except UnicodeEncodeError:
					print("EXCEPTION")
		print()
		time.sleep(0.3)
