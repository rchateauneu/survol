/*
https://virtualizationreview.com/articles/2019/04/19/using-dtrace-for-windows.aspx
*/

dtrace:::BEGIN
{
  trace("Hello World!");
  exit(0);
}