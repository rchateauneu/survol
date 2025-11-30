#!/usr/sbin/dtrace -s

/*
https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/devtest/dtrace-code-samples.md

Disk Usage by Name

dtrace: failed to compile script diskusagebyname_test.d: line 36: syntax error near "nt`_EPROCESS"
*/

#pragma D option quiet
#pragma D option destructive


intptr_t curptr;
struct nt`_EPROCESS *eprocess_ptr;
int found;
int firstpass;
BEGIN
{
	curptr = (intptr_t) ((struct nt`_LIST_ENTRY *) (void*)&nt`PsActiveProcessHead)->Flink;	
	found = 0;
	firstpass = 1;
	bytesread = 0;
	byteswrite = 0;
	readcount = 0;
	writecount = 0;
	flushcount = 0;
}

tick-1ms

/found == 0/

{
/* use this for pointer parsing */
	if (found == 0)
	{
		eprocess_ptr = (struct nt`_EPROCESS *)(curptr - offsetof(nt`_EPROCESS, ActiveProcessLinks));
		processid = (string) eprocess_ptr->ImageFileName;

		if ($1 == processid)
		{
			found = 1;
		}

		else 
		{
			curptr = (intptr_t) ((struct nt`_LIST_ENTRY *) (void*)curptr)->Flink;
		}
	}		
}

tick-2s

{
	system ("cls");
	if (found == 1)
	{
		if (firstpass)
		{
			firstpass = 0;
			bytesread = (unsigned long long) eprocess_ptr->DiskCounters->BytesRead;
			byteswrite = (unsigned long long) eprocess_ptr->DiskCounters->BytesWritten;
			readcount = eprocess_ptr->DiskCounters->ReadOperationCount;
			writecount = eprocess_ptr->DiskCounters->WriteOperationCount;
			flushcount =  eprocess_ptr->DiskCounters->FlushOperationCount;
		}

		else
		{
			bytesread = (unsigned long long)  (eprocess_ptr->DiskCounters->BytesRead - bytesread);
			byteswrite = (unsigned long long)  (eprocess_ptr->DiskCounters->BytesWritten - byteswrite);
			readcount = eprocess_ptr->DiskCounters->ReadOperationCount - readcount;
			writecount = eprocess_ptr->DiskCounters->WriteOperationCount - writecount;		
			flushcount = eprocess_ptr->DiskCounters->FlushOperationCount - flushcount;

			printf("*** Reports disk read/write every second *** \n");
			printf("Process name: %s\n", eprocess_ptr->ImageFileName);
			printf("Process Id: %d\n", (int) eprocess_ptr->UniqueProcessId);
			printf("Bytes Read %llu \n",  (unsigned long long) bytesread);
			printf("Bytes Written %llu \n", (unsigned long long) byteswrite);
			printf("Read Operation Count %d \n", readcount);
			printf("Write Operation Count %d \n",writecount);
			printf("Flush Operation Count %d \n", flushcount);

			bytesread = (unsigned long long) eprocess_ptr->DiskCounters->BytesRead;
			byteswrite = (unsigned long long) eprocess_ptr->DiskCounters->BytesWritten;
			readcount = eprocess_ptr->DiskCounters->ReadOperationCount;
			writecount = eprocess_ptr->DiskCounters->WriteOperationCount;
			flushcount =  eprocess_ptr->DiskCounters->FlushOperationCount;		
		}		
	}

	else
	{
		printf("No matching process found for %s \n", $1);
		exit(0);
	}
}