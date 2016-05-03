import pefile
import sys

# https://recon.cx/en/f/lightning-ecarrera-win32-static-analysis-in-python.pdf

pe = pefile.PE(sys.argv[1])

#print hex(pe.VS_VERSIONINFO.Length)
#print hex(pe.VS_VERSIONINFO.Type)
#print hex(pe.VS_VERSIONINFO.ValueLength)
#print hex(pe.VS_FIXEDFILEINFO.Signature)
#print hex(pe.VS_FIXEDFILEINFO.FileFlags)
#print hex(pe.VS_FIXEDFILEINFO.FileOS)
#print(dir(pe))


for sec in pe.sections:
	print(sec.Name,hex(sec.VirtualAddress), hex(sec.Misc_VirtualSize), sec.SizeOfRawData)

for entry in pe.DIRECTORY_ENTRY_IMPORT:
	print dir(entry)
	print entry.struct
	print entry.dll
	for imp in entry.imports:
		print '\t',hex(imp.address), imp.name

for fileinfo in pe.FileInfo:
  print("Key=%s"% fileinfo.Key)
  if fileinfo.Key == 'StringFileInfo':
    for st in fileinfo.StringTable:
      for entry in st.entries.items():
        print '%s: %s' % (entry[0], entry[1])
  elif fileinfo.Key == 'VarFileInfo':
    for var in fileinfo.Var:
      print '%s: %s' % var.entry.items()[0]