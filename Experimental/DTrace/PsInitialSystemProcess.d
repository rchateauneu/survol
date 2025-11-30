/*
PsInitialSystemProcess points to the EPROCESS structure for the system process.
*/

BEGIN{
	print(*(struct nt`_EPROCESS  *) nt`PsInitialSystemProcess);
	toto = 123;
	exit(0);
}
