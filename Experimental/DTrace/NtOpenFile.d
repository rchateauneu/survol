/*
https://virtualizationreview.com/articles/2019/04/19/using-dtrace-for-windows.aspx
*/

syscall::NtOpenFile:entry
/* /pid == 11768/ */
{ 
  printf("%s", execname);
  
  /*
  dtrace: error on enabled probe ID 1 (ID 538: syscall::NtOpenFile:entry): invalid address (0x2e9a1e8) in action #2
  printf("%s %s", execname, stringof(arg0));
  */
}
  
  