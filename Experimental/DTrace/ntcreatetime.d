/*
https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace-programming

dtrace: script 'ntcreatetime.d' matched 2 probes
CPU     ID                    FUNCTION:NAME
  4    191       NtCreateUserProcess:return  [Caller svchost.exe]: Time taken to return from create process is 3693 MicroSecond
*/

syscall::NtCreateUserProcess:entry
{
    self->ts = timestamp;
}

syscall::NtCreateUserProcess:return
{
    printf(" [Caller %s]: Time taken to return from create process is %d MicroSecond \n", execname, (timestamp - self->ts)/ 1000);
	printf("Pid=%d\n", pid);
}
