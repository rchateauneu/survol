# This scripts does various scenarios of execution of the script dockit.py,
# and attempt to rebuild some of input tests using the test programs
# and other various Linux commands, and tests the generated files.
# Some tests cannot be easily recreated.
# It tries to rerun the tests given in the dockit_readme.txt file.

DOCKIT=../../survol/survol/scripts/dockit.py

#  -h,--help                     This message.
#  -v,--verbose                  Verbose mode (Cumulative).
#  -w,--warning                  Display warnings (Cumulative).
#  -s,--summary <CIM class>      Prints a summary at the end: Start end end time stamps, executable name,
#                                loaded libraries, read/written/created files and timestamps, subprocesses tree.
#                                Examples: -s 'Win32_LogicalDisk.DeviceID="C:",Prop1="Value1",Prop2="Value2"'
#                                          -s 'CIM_DataFile:Category=["Others","Shared libraries"]'
#  -D,--dockerfile               Generates a dockerfile.
#  -p,--pid <pid>                Monitors a running process instead of starting an executable.
#  -f,--format TXT|CSV|JSON      Output format. Default is TXT.
#  -F,--summary-format TXT|XML   Summary output format. Default is XML.
#  -i,--input <file name>        trace command input file.
#  -l,--log <filename prefix>    trace command log output file.
#
#  -t,--tracer strace|ltrace|cdb command for generating trace log

DOCKIT_TMPDIR=/tmp/dockit.$$

$DOCKIT -l ${DOCKIT_TMPDIR}/tst_01_ls ls

# $DOCKIT -t strace -l UnitTests/mineit_simple_perl_file_write perl TestProgs/write_file_in_perl.pl
# $DOCKIT -t ltrace -l UnitTests/mineit_simple_perl_file_write perl TestProgs/write_file_in_perl.pl
