# Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
# Authors: Michal Minar <miminar@redhat.com>

"""
Various utilities.
"""
from collections import defaultdict
import inspect
import pywbem
import re
import os
import socket

_RE_URL_FUNC = re.compile(r'^[A-Z][a-z_A-Z0-9]+$')

def cmp_pnames(klass):
    """
    Wrapper for comparing function for class property names, which
    places keys before non-key properties.
    It accepts instance of pywbem.CIMClass.
    """
    def _cmp(aname, bname):
        """
        compare function for sorting class property names placing
        keys before non-keys
        """
        is_key = lambda key: (
                    klass and klass.properties.has_key(key)
                and klass.properties[key].qualifiers.has_key('key'))
        is_key_a = is_key(aname)
        is_key_b = is_key(bname)
        if is_key_a and is_key_b:
            return cmp(aname, bname)
        if is_key_a and not is_key_b:
            return -1
        if not is_key_a and is_key_b:
            return 1
        return cmp(aname, bname)
    return _cmp

def cmp_params(klass):
    """
    Wrapper for comparing class/instance attribute names represented
    by dictionaries.
    @param klass is instance of pywbem.CIMClass
    """
    _cmp_orig = cmp_pnames(klass)
    def _cmp(aname, bname):
        """
        compare function for class properties represented as python
        dictionaries
        """
        if aname['is_method'] and not bname['is_method']:
            return -1
        if not aname['is_method'] and bname['is_method']:
            return 1
        return _cmp_orig(aname['name'], bname['name'])
    return _cmp

def inames_equal(op1, op2):
    """
    Compares 2 object paths for equality.
    host attribute is ignored.
    """
    if (  not isinstance(op1, pywbem.CIMInstanceName)
       or not isinstance(op2, pywbem.CIMInstanceName)
       or op1.classname != op2.classname
       or op1.namespace != op2.namespace
       or (  pywbem.NocaseDict(op1.keybindings)
          != pywbem.NocaseDict(op2.keybindings))):
        return False
    return True

def base_script(request):
    """
    @return base url of yawn application
    """
    path_parts = [p for p in
        request.environ['SCRIPT_NAME'].split('/') if p ]
    if len(path_parts) and _RE_URL_FUNC.match(path_parts[-1]):
        try:
            if inspect.isfunction(eval(path_parts[-1])):
                path_parts.pop(len(path_parts) - 1)
        except Exception:
            pass
    if len(path_parts) and path_parts[-1].startswith('index.'):
        path_parts.pop(len(path_parts[-1]))
    return "/" + "/".join(path_parts)

def get_user_pw(request):
    """
    Obtains user's credentials from request object.
    @return (username, password) if credentials are available
    and (None, None) otherwise
    """
    if 'Authorization' not in request.headers:
        return (None, None)
    auth = request.authorization
    return (auth.username, auth.password)

def is_selinux_running():
    """
    @return True if selinux is available on system and enabled
    """
    try:
        import selinux
        if selinux.security_getenforce() < 0:
            return False
    except (ImportError, OSError):
        return False
    return True

def rdefaultdict():
    """
    Recursive defaultdict factory.
    Usage:
        d = rdefaultdict()
        d[1] = "string"
        d[2]["second_level"] = []
    """
    return defaultdict(rdefaultdict)

def get_hostname():
	return socket.gethostname()
	
