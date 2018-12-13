import r2pipe

# Temporary.
import os
os.environ["PATH"] = os.environ["PATH"] + ";C:\\Users\\rchateau\\AppData\\Local\\Programs\\radare2"

namExe = "C:\\Windows\\System32\\notepad.exe"
namDll = "C:\\Windows\\System32\\normaliz.dll"

r = r2pipe.open(namDll)

cmds = ["pd 10","iI","ie","iS","iz","afl"]
for cm in cmds:
	print("Command=",cm)
	print(r.cmd(cm))

print(r.cmdj("aoj")[0]['size'])
r.quit()