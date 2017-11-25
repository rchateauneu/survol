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



def IconToFile(hlib,tmpDirName,group_name):
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
    sys.stderr.write("icon_name=%s\n"%str(icon_name))
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

    # Need temp directory or generate image on the fly, for inclusion into an HTML page.
    # Temp file visible from HTTP server.
    # An alternative is to send the file content to a socket stream.
    # MIME type is "image/bmp"
    imgFilNam = "icon-%03dx%03d-%05d-%03d.bmp" % (bminfo.bmWidth, bminfo.bmHeight, group_name, icon_name)
    if tmpDirName:
        imgFilNam = tmpDirName + imgFilNam
    sys.stderr.write("Generating %s\n"%imgFilNam)
    hbmp.SaveBitmapFile(hcdc, imgFilNam)
    win32gui.DestroyIcon(hIconRet)
    return imgFilNam

def DispOneIcon(pathName,tmpDirName,group_name):
    # Using LoadLibrary (rather than CreateFile) is required otherwise
    # LoadResource, FindResource and others will fail
    hlib = win32api.LoadLibraryEx(pathName, 0, 2)

    return IconToFile(hlib,tmpDirName,group_name)

# This generates one file per icon, and is used for testing.
def ExtractIconFromExe(pathName,tmpDirName):
    # Using LoadLibrary (rather than CreateFile) is required otherwise
    # LoadResource, FindResource and others will fail
    hlib = win32api.LoadLibraryEx(pathName, 0, 2)

    # get icon groups, default is the first group
    icon_groups = win32api.EnumResourceNames(hlib, win32con.RT_GROUP_ICON)

    for group_name in icon_groups:
        IconToFile(hlib,tmpDirName,group_name)

def GetIconNamesList(pathName):
    # Using LoadLibrary (rather than CreateFile) is required otherwise
    # LoadResource, FindResource and others will fail
    hlib = win32api.LoadLibraryEx(pathName, 0, 2)

    # get icon groups, default is the first group
    icon_groups = win32api.EnumResourceNames(hlib, win32con.RT_GROUP_ICON)

    return icon_groups


exeName = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
tmpDirName = ""
ExtractIconFromExe(exeName,tmpDirName)