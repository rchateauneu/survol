/*
https://virtualizationreview.com/articles/2019/04/19/using-dtrace-for-windows.aspx
*/

syscall:::
/pid == 11768/ 
{ 
  printf ("%s called. Output of first argument is %d \n", execname, arg0); 
}
  