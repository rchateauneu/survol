# Ca n apporte rien de plus par rapport a psutil.

"""
Enumerates active processes as seen under windows Task Manager on Win NT/2k/XP using PSAPI.dll
(new api for processes) and using ctypes.Use it as you please.

Based on information from http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q175030&ID=KB;EN-US;Q175030

By Eric Koome
email ekoome@yahoo.com
license GPL
"""
from ctypes import *

#PSAPI.DLL
psapi = windll.psapi
#Kernel32.DLL
kernel = windll.kernel32

def EnumProcesses():
	arr = c_ulong * 256
	lpidProcess= arr()
	cb = sizeof(lpidProcess)
	cbNeeded = c_ulong()
	hModule = c_ulong()
	count = c_ulong()
	modname = c_buffer(30)
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ = 0x0010
	
	#Call Enumprocesses to get hold of process id's
	psapi.EnumProcesses(byref(lpidProcess),
						cb,
						byref(cbNeeded))
	
	#Number of processes returned
	nReturned = cbNeeded.value/sizeof(c_ulong())
	

	# pidProcess = [i for i in lpidProcess][:nReturned]
	pidProcess = []
	for k in range(0,int(nReturned)):
		#print("k="+str(k))
		#print("lpidProcess[k]=" + str(lpidProcess[k]) )
		# pidProcess.append( lpidProcess[k] )

		# for pid in pidProcess:
		pid = lpidProcess[k]
		print("pid="+str(pid))
		#Get handle to the process based on PID
		hProcess = kernel.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
		if not hProcess:
			continue

		for i in range(modname._length_):
			# modname[i]='\x00'
			modname[i]=bytes( [0] )

		psapi.EnumProcessModules(hProcess, byref(hModule), sizeof(hModule), byref(count))
		print("count="+str(count))
		psapi.GetModuleBaseNameA(hProcess, hModule.value, modname, sizeof(modname))
		#print("modname="+str(modname))
		toto = [ i for i in modname if i != '\x00']
		#print( "".join([ i for i in modname if i != '\x00']) )
		#print("toto="+str(toto))

		tutu = [ i.decode("utf-8") for i in modname if i != bytes( [0] )]
		#print("tutu="+str(tutu))

		tata = "".join(tutu)
		print("tata="+tata)

			
		#-- Clean up
		#for i in range(modname._length_):
		#	modname[i]='\x00'
			
		kernel.CloseHandle(hProcess)

if __name__ == '__main__':
	EnumProcesses()