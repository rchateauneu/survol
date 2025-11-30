#!/usr/sbin/dtrace -s

/*
https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/devtest/dtrace-code-samples.md
*/

/*
About the error message:
dtrace: failed to compile script comparequid_test.d: line 9: expected predicate and/or actions following probe description

https://opensource.apple.com/source/dtrace/dtrace-118/libdtrace/dt_grammar.y.auto.html

If the input stream is a file, do not permit a probe
specification without / <pred> / or { <act> } after
it.  This can only occur if the next token is EOF or
an ambiguous predicate was slurped up as a comment.
We cannot perform this check if input() is a string
because dtrace(1M) [-fmnP] also use the compiler and
things like dtrace -n BEGIN have to be accepted.
*/


/*
nt`_GUID guidcmp;
*/
struct nt`_EPROCESS *eprocess_ptr;
struct nt`_GUID *guidcmp_ptr;

/* Sleep After GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da */
dtrace:::BEGIN
{
    printf("Begin\n");
    guidcmp.Data1 = 0x29f6c1db;
    guidcmp.Data2 = 0x86da;
    guidcmp.Data3 = 0x48c5;
    guidcmp.Data4[0] = 0x9f;
    guidcmp.Data4[1]  = 0xdb;
    guidcmp.Data4[2]  = 0xf2;
    guidcmp.Data4[3]  = 0xb6;
    guidcmp.Data4[4]  = 0x7b;
    guidcmp.Data4[5]  = 0x1f;
    guidcmp.Data4[6]  = 0x44;
    guidcmp.Data4[7]  = 0xda;
}

pid$target:PowrProf:PowerReadACValueIndexEx:entry 
{
	print(*(struct nt`_EPROCESS  *) nt`PsInitialSystemProcess);
	print(*(struct nt`_GUID  *) nt`PsInitialSystemProcess);
	toto = copyin(arg2, sizeof(nt`_GUID));
	nt`_GUID * tyty;
	nt`_GUID tata;
	tutu = (nt`_GUID *)copyin(arg2, sizeof(nt`_GUID));

	cidstr = (nt`_GUID *) (copyin(arg2, sizeof(nt`_GUID)));

	printf("\nPrinting GUID to compare\n");
	print(guidcmp);

	printf("\nPrinting GUID received \n");
	print(*cidstr);

	if ( 	(cidstr->Data1 == guidcmp.Data1) &&
		(cidstr->Data2 == guidcmp.Data2) &&
		(cidstr->Data3 == guidcmp.Data3) &&
		(cidstr->Data4[0] == guidcmp.Data4[0]) &&
		(cidstr->Data4[1] == guidcmp.Data4[1]) &&
		(cidstr->Data4[2] == guidcmp.Data4[2]) &&
		(cidstr->Data4[3] == guidcmp.Data4[3]) &&
		(cidstr->Data4[4] == guidcmp.Data4[4]) &&
		(cidstr->Data4[5] == guidcmp.Data4[5]) &&
		(cidstr->Data4[6] == guidcmp.Data4[6]) &&
		(cidstr->Data4[7] == guidcmp.Data4[7])	)
	{
		printf("GUID matched \n");
	}
	else
	{
		printf("No match");
	}
}

dtrace:::END
{
    printf("End\n");
}