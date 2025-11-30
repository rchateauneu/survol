#!/usr/sbin/dtrace -s

/*
https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/devtest/dtrace-code-samples.md

dtrace: failed to compile script heapfree_test.d: line 23: invalid probe description "pid$1:ntdll:RtlFreeHeap:entry": Undefined macro variable in probe description
*/

/* Mark script destructive as we call "cls" in the tick-1sec provider*/
#pragma D option destructive

/* Program to calculate time taken in RtlFreeHeap function. Hit Ctrl-C to break. */ 

dtrace:::BEGIN 
{
	counter1 = 0;

}

tick-1sec
{
	system ("cls");
	printf("count of function hit = %d << Press Ctrl-C to exit >> \n", counter1);

}

/* Instrument entry of RtlFreeHeap*/

pid$1:ntdll:RtlFreeHeap:entry
{ 
	/* self is thread local */
	self->ts = timestamp;
	self->depth = 0;
	counter1++;
} 

pid$1:ntdll:RtlFreeHeap:return
/self->ts/
{
	this->ts = timestamp - self->ts;
	@disttime = quantize(this->ts); 
	@funcName[probemod,probefunc] = max(this->ts);	
	self->ts = 0;
}


pid$1:::entry
/ self->ts /
{
	self->functime[self->depth] = timestamp;
	self->depth++;
}

pid$1:::return
/ self->ts /
{
	if (self->depth > 0)
	{
		self->depth--;
		/* this is a local scope */
		this->ts = timestamp - self->functime[self->depth];
		@funcName[probemod,probefunc] = max(this->ts);
	}
}

END

{
	system ("cls");
	/* Print overall time distribution for RtlFreeHeap */
	printa (@disttime);
	/* Print top 15 functions along with average time spent executing them */
	trunc (@funcName, 15);
	
	printa( @funcName);
	
}