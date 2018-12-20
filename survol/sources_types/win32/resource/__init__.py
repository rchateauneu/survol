"""
Resource embedded in a Windows file.
"""

# https://stackoverflow.com/questions/23263599/how-to-extract-128x128-icon-bitmap-data-from-exe-in-python
# Use wchar_t function version (FindResourceW rather than FindResourceA)
from __future__ import unicode_literals

import sys
import win32con
import win32api
import win32file
import win32gui
import win32ui
import pywintypes
import ctypes
import ctypes.util

import os
import lib_common
import lib_util
import lib_properties

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms648009%28v=vs.85%29.aspx
# Predefined resource types:
# RT_ACCELERATOR Accelerator table.
# RT_ANICURSOR Animated cursor.
# RT_ANIICON Animated icon.
# RT_BITMAP Bitmap resource.
# RT_CURSOR Hardware-dependent cursor resource.
# RT_DIALOG Dialog box.
# RT_DLGINCLUDE Allows a resource editing tool to associate a string with an .rc file.
# RT_FONT Font resource.
# RT_FONTDIR Font directory resource.
# RT_GROUP_CURSOR Hardware-independent cursor resource.
# RT_GROUP_ICON Hardware-independent icon resource.
# RT_HTML HTML resource.
# RT_ICON Hardware-dependent icon resource.
# RT_MANIFEST Side-by-Side Assembly Manifest.
# RT_MENU Menu resource.
# RT_MESSAGETABLE Message-table entry.
# RT_PLUGPLAY Plug and Play resource.
# RT_RCDATA Application-defined resource (raw data).
# RT_STRING String-table entry.
# RT_VERSION Version resource.
# RT_VXD VXD.

def EntityOntology():
	return ( ["Name","GroupName"], )

# Given a resources characteristics (File name and group), it returns a string suitable for printing.
def EntityName(entity_ids_arr):
	entity_id = entity_ids_arr[0]
	group_name = entity_ids_arr[1]
	# A file name can be very long, so it is truncated.
	file_basename = os.path.basename(entity_id)
	if file_basename == "":
		return entity_id + ":" + group_name
	else:
		return file_basename + ":" + group_name



# The group might be a string or an integer and its type must be kept.
def IconToFile(hlib,group_name):
    DEBUG("IconToFile group_name=%s",str(group_name))
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    libc.memcpy.restype = ctypes.c_char_p

    # patch FindResourceW, ctypes.windll.kernel32.SizeofResource
    FindResourceW = ctypes.windll.kernel32.FindResourceW
    FindResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    FindResourceW.restype = ctypes.c_void_p
    SizeofResource = ctypes.windll.kernel32.SizeofResource
    SizeofResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    SizeofResource.restype = ctypes.c_size_t

    hRes = win32api.LoadResource(hlib, win32con.RT_GROUP_ICON, group_name)
    mem_icon_dir = ctypes.windll.kernel32.LockResource(hRes)

    # 32 bits color; 16 and 256 colors are too old

    icon_size = 256
    icon_name = ctypes.windll.user32.LookupIconIdFromDirectoryEx(mem_icon_dir, True, icon_size, icon_size, 0x00000000);
    DEBUG("icon_name=%s",str(icon_name))
    hResInfo = FindResourceW(hlib, icon_name, win32con.RT_ICON)
    size = ctypes.windll.kernel32.SizeofResource(hlib, hResInfo)
    rec = win32api.LoadResource(hlib, win32con.RT_ICON, icon_name)
    mem_icon = ctypes.windll.kernel32.LockResource(rec)

    # And this is some differ (copy data to Python buffer)
    binary_data = (ctypes.c_ubyte * size)()
    libc.memcpy(binary_data, mem_icon, size)
    hIconRet = ctypes.windll.user32.CreateIconFromResourceEx(binary_data, size, True, 0x00030000, 0, 0, 0x00000000);
    info = win32gui.GetIconInfo(hIconRet)
    bminfo = win32gui.GetObject(info[4])

    # generate bitmap by drawing the icon
    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
    hbmp = win32ui.CreateBitmap()
    hbmp.CreateCompatibleBitmap(hdc, bminfo.bmWidth, bminfo.bmHeight)
    hcdc = hdc.CreateCompatibleDC()
    hcdc.SelectObject(hbmp)
    win32gui.DrawIconEx(hcdc.GetHandleOutput(), 0, 0, hIconRet, bminfo.bmWidth, bminfo.bmHeight, 0, 0, 0x0003)

    # MIME type is "image/bmp"
    # The group name might be a number: 110 etc... or a string such as 'ICO_MYCOMPUTER'.

    # This is the prefix of the temporary BMP file name containing the extracted icon.
    imgFilNamPrefix = "icon-%03dx%03d-%s-%03d" % (bminfo.bmWidth, bminfo.bmHeight, str(group_name), icon_name)

    # The destructor will remove the file.
    objTempFile = lib_common.TmpFile(imgFilNamPrefix,"bmp")

    imgFilNam = objTempFile.Name
    DEBUG("Generating %s",imgFilNam)
    hbmp.SaveBitmapFile(hcdc, imgFilNam)
    win32gui.DestroyIcon(hIconRet)
    return objTempFile

# For a Windows executable file, it returns the list of resource icons groups it contains.
def GetIconNamesList(pathName):
    # Using LoadLibrary (rather than CreateFile) is required otherwise
    # LoadResource, FindResource and others will fail
	try:
		hlib = win32api.LoadLibraryEx(pathName, 0, 2)

		# get icon groups, default is the first group
		iconGroups = win32api.EnumResourceNames(hlib, win32con.RT_GROUP_ICON)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("GetIconNamesList pathName=%s caught:%s" % ( pathName, str(exc) ) )

    # Strings and integers.
	return iconGroups

mimeTypeResource = "image/bmp"

# It receives as CGI arguments, the entity type which is "HttpUrl_MimeDocument", and the filename.
# It must then return the content of the file, with the right MIME type,

def DisplayAsMime(grph,node,entity_ids_arr):

    fileName = entity_ids_arr[0]
    groupName = entity_ids_arr[1]

    DEBUG("fileName=%s groupName=%s", fileName, groupName )

    # Using LoadLibrary (rather than CreateFile) is required otherwise
    # LoadResource, FindResource and others will fail
    hlib = win32api.LoadLibraryEx(fileName, 0, 2)

    DEBUG("fileName=%s groupName=%s",fileName,str(groupName))
    try:
        groupName = int(groupName)
    except:
        pass

    # The destructor will remove the temporary file.
    objTempFile = IconToFile(hlib,groupName)

    rsrcFilNam = objTempFile.Name

    try:
        lib_util.CopyFile( mimeTypeResource, rsrcFilNam )
    except Exception:
        exc = sys.exc_info()[1]
        lib_common.ErrorMessageHtml("DisplayAsMime rsrcFilNam=%s, mime_type=%s caught:%s" % ( rsrcFilNam, mime_type, str(exc) ) )
