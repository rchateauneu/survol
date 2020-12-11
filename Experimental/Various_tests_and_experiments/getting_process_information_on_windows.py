"""
Enumerates active processes as seen under windows Task Manager on Win NT/2k/XP using PSAPI.dll
(new api for processes) and using ctypes.Use it as you please.

Based on information from http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q175030&ID=KB;EN-US;Q175030

By Eric Koome
email ekoome@yahoo.com
license GPL
"""
from ctypes import *

psapi = windll.psapi
kernel = windll.kernel32

def DispPid(pid):
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ = 0x0010
	print("Pid="+str(pid))
		
	#Get handle to the process based on PID
	hProcess = kernel.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
	if hProcess:

		ModuType = c_ulong * 512
		hModuleArr = ModuType()
		rawCntModules = c_ulong()
		psapi.EnumProcessModules(hProcess, byref(hModuleArr), sizeof(hModuleArr), byref(rawCntModules))
		nbModules = int( rawCntModules.value/sizeof(c_ulong()) )
		if nbModules >= 512:
			raise Exception("Disaster overrun")

		print("nbModules="+str(nbModules))

		modname = c_buffer(256)
		for idx in range( 0, nbModules ):
			retLen = psapi.GetModuleFileNameExA(hProcess, hModuleArr[idx], modname, sizeof(modname))
			tab = modname[:retLen]
			print( "   => " + str(tab) )
			
		kernel.CloseHandle(hProcess)



def EnumProcesses():
	arr = c_ulong * 256
	lpidProcess= arr()
	cb = sizeof(lpidProcess)
	cbNeeded = c_ulong()
	
	#Call Enumprocesses to get hold of process id's
	psapi.EnumProcesses(byref(lpidProcess), cb, byref(cbNeeded))
	
	#Number of processes returned
	nReturned = int( cbNeeded.value/sizeof(c_ulong()) )
	
	pidProcess = [i for i in lpidProcess][:nReturned]
	
	for pid in pidProcess:
		DispPid(pid)

if __name__ == '__main__':
	EnumProcesses()
