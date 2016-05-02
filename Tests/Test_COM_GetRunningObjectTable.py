import os
import pythoncom
import win32api
import win32com.client

# Jamais reussi a lui faire afficher quoique ce soit et pourtant ca devrait.
context = pythoncom.CreateBindCtx (0)
print("Starting")
for moniker in pythoncom.GetRunningObjectTable ():
  print("OK")
  name = moniker.GetDisplayName (context, None)
  print(name)
print("Finished")