@REM The goal is to use procmon similarly to strace or ltrace.
@REM procmon is very commonly used and stable.
@REM
@REM https://blogs.msdn.microsoft.com/yash/2009/03/23/using-procmon-in-command-line/

set PM=C:\Program_Extra\SysinternalsSuite\Procmon.exe

@REM /AcceptEula : Automatically accepts the license and bypasses the EULA dialog.
start %PM% /quiet /minimized /AcceptEula /backingfile C:\temp\notepad.pml

%PM% /waitforidle

start /wait notepad.exe

%PM% /terminate