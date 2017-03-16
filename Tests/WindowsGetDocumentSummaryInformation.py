# http://timgolden.me.uk/python/win32_how_do_i/get-document-summary-info.html
# Most files, on the property tabs, have a tab called Summary. It includes things like Title, Subject and Keywords.
# In the case of certain files, such as those from Microsoft Office,
# there may be extra document-specific fields and also a user-defined set.
# These are part of the Structured Storage mechanism which embeds mini-filesystems inside files.

import os, sys
import pythoncom
from win32com.shell import shell
from win32com import storagecon

FORMATS = {
    pythoncom.FMTID_SummaryInformation : "SummaryInformation",
    pythoncom.FMTID_DocSummaryInformation : "DocSummaryInformation",
    pythoncom.FMTID_UserDefinedProperties : "UserDefinedProperties"
}
PROPERTIES = {
    pythoncom.FMTID_SummaryInformation : dict (
        (getattr (storagecon, d), d) for d in dir (storagecon) if d.startswith ("PIDSI_")
    ),
    pythoncom.FMTID_DocSummaryInformation : dict (
        (getattr (storagecon, d), d) for d in dir (storagecon) if d.startswith ("PIDDSI_")
    )
}

STORAGE_READ = storagecon.STGM_READ | storagecon.STGM_SHARE_EXCLUSIVE

def property_dict (property_set_storage, fmtid):
    properties = {}
    try:
        property_storage = property_set_storage.Open (fmtid, STORAGE_READ)
    except pythoncom.com_error, error:
        if error.strerror == 'STG_E_FILENOTFOUND':
            return {}
        else:
            raise

    for name, property_id, vartype in property_storage:
        if name is None:
            name = PROPERTIES.get (fmtid, {}).get (property_id, None)
        if name is None:
            name = hex (property_id)
        try:
            for value in property_storage.ReadMultiple ([property_id]):
                properties[name] = value
        #
        # There are certain values we can't read; they
        # raise type errors from within the pythoncom
        # implementation, thumbnail
        #
        except TypeError:
            properties[name] = None
    return properties

def property_sets (filepath):
	sys.stderr.write("file=%s\n"%filepath)
	pidl, flags = shell.SHILCreateFromPath (os.path.abspath (filepath), 0)
	property_set_storage = shell.SHGetDesktopFolder ().BindToStorage (pidl, None, pythoncom.IID_IPropertySetStorage)
	for fmtid, clsid, flags, ctime, mtime, atime in property_set_storage:
		yield FORMATS.get (fmtid, unicode (fmtid)), property_dict (property_set_storage, fmtid)
		if fmtid == pythoncom.FMTID_DocSummaryInformation:
			fmtid = pythoncom.FMTID_UserDefinedProperties
			user_defined_properties = property_dict (property_set_storage, fmtid)
			if user_defined_properties:
				yield FORMATS.get (fmtid, unicode (fmtid)), user_defined_properties

if __name__ == '__main__':
	for name, properties in property_sets (sys.argv[1]):
		print name
		for k, v in properties.items ():
			try:
				sys.stderr.write("    %s => %s\n" % (k,v))
			except:
				sys.stderr.write("    %s => %s\n" % (k,str(sys.exc_info()[1])))

			# print "  ", k, "=>", v
