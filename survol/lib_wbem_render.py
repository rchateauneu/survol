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
Utilities and functions for template rendering.
"""
import base64
#import cPickle
import datetime
from collections import defaultdict
#import mako.lookup
#import mako.exceptions
import pywbem
import re
import types
import zlib
# from pywbem_yawn import util
import lib_wbem_util

_RE_ERRNO_13 = re.compile(r'^socket\s+error\s*:.*errno\s*13', re.I)

CIM_ERROR2TEXT = defaultdict(lambda: "OTHER_ERROR", {
    1  : "FAILED",
    2  : "ACCESS_DENIED",
    3  : "INVALID_NAMESPACE",
    4  : "INVALID_PARAMETER",
    5  : "INVALID_CLASS",
    6  : "NOT_FOUND",
    7  : "NOT_SUPPORTED",
    8  : "CLASS_HAS_CHILDREN",
    9  : "CLASS_HAS_INSTANCES",
    10 : "INVALID_SUPERCLASS",
    11 : "ALREADY_EXISTS",
    12 : "NO_SUCH_PROPERTY",
    13 : "TYPE_MISMATCH",
    14 : "QUERY_LANGUAGE_NOT_SUPPORTED",
    15 : "INVALID_QUERY",
    16 : "METHOD_NOT_AVAILABLE",
    17 : "METHOD_NOT_FOUND"
})

# Does not work with Python 3.
class SafeString(unicode): #pylint: disable=R0924,R0904,C0111
    """
    when this type of string is passed to template, it will be not escaped
    upon rendering if safe param is True
    """
    def __init__(self, text):
        unicode.__init__(self, text)
        self.safe = True

def render_cim_error_msg(err):
    """
    Generates error from pywbem.CIMError exception as html.
    @return generated message
    """
    if not isinstance(err, pywbem.CIMError):
        raise TypeError("err must be a CIMError")
    errstr = err[1]
    if errstr.startswith('cmpi:'):
        errstr = errstr[5:]
    elif 'cmpi:Traceback' in errstr:
        errstr = errstr.replace('cmpi:Traceback', 'Traceback')
    errstr = errstr.replace('<br>', '\n').replace('&lt;br&gt;', '\n')
    return errstr

def check_cause(exception):
    """
    Check, whether exception was thrown due to some known problem.
    If it's known, provide some hints for user, so that he can fix it.
    @return { 'description' : dsc, 'fix': fix} in case, that
    problem is known, None otherwise.
    """
    if (  not isinstance(exception, pywbem.CIMError)
       or exception.args[0] != 0):
        return
    if (   _RE_ERRNO_13.match(exception.args[1])
       and lib_wbem_util.is_selinux_running()):
        import selinux
        if not selinux.security_get_boolean_active(
                "httpd_can_network_connect"):
            cause = ( "SELinux prevents YAWN"
                      " from connecting to the network using TCP.")
            solution = SafeString('Please run as root:<br/>'
                '<span class="code_snippet">'
                '&nbsp;&nbsp;setsebool -P httpd_can_network_connect 1</span>')
            return { "description" : cause, "fix" : solution }

class Renderer(object):
    """
    A context manager used to encapsulate pywbem calls obtaining information
    for template rendering. If a pywbem CIMError occurs, it renders given
    template with error variable. Otherwise renders a template.

    Usage:
        with Renderer(lookup, "template_name.mako", **kwargs) as r:
           connection.GetInstance(...) # get informations
           ...
           r["var_name"] = val1        # set template variables
           r["var_name"] = val2
        return r.result                # rendered html (even in case
                                       # of exception)
    """

    def __init__(self, lookup, template, debug=False, **kwargs):
        if not isinstance(lookup, mako.lookup.TemplateLookup):
            raise TypeError("lookup must be an instance of"
                    " mako.lookup.TemplateLookup")
        if not isinstance(template, basestring):
            raise TypeError("template must be a string with the"
                    " name of template to render")
        self._debug = debug
        self._lookup = lookup
        self._template = template
        self._template_kwargs = kwargs
        # if any exception occurs within the render
        # context, this variable is set to (exc_type, exc_value, exc_tb)
        self._exception = None
        self._result = None

    @property
    def lookup(self):
        """
        @return make templates lookup object
        """
        return self._lookup

    @property
    def template(self):
        """
        @return name of template to render
        """
        return self._template

    @property
    def template_kwargs(self):
        """
        @return copy of keyword arguments for template rendering
        """
        return self._template_kwargs.copy()

    @template_kwargs.setter
    def template_kwargs(self, kwargs):
        """
        Overwrite keyword arguments dictionary for template.
        """
        self._template_kwargs = kwargs
        return kwargs

    @property
    def result(self):
        """
        @return rendered template as string
        """
        if self._result is None:
            template = self._lookup.get_template(self._template)
            if (  self._exception is not None
               and self._exception[0] is not pywbem.CIMError):
                self._result = mako.exceptions.html_error_template().render()
            else:
                kwargs = self._template_kwargs
                if self._exception is not None: # pywbem.CIMError
                    exc_val = self._exception[1]
                    cause = check_cause(self._exception[1])
                    if cause:
                        kwargs["error_cause_description"] = cause["description"]
                        kwargs["error_cause_suggestion"] = cause["fix"]
                    kwargs["cim_error"] = "%d (%s)" % (exc_val.args[0],
                            CIM_ERROR2TEXT[exc_val.args[0]])
                    kwargs["cim_error_msg"] = render_cim_error_msg(exc_val)
                self._result = template.render(**kwargs)
        return self._result

    def __enter__(self):
        """
        Enter method for context management.
        @see __exit__
        """
        self._exception = None
        self._result = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        If an exception like pywbem.CIMError is raised, it will be
        saved for rendering provided template.
        If in debugging mode, let it be propagated upwards.
        """
        if exc_type is not None:
            self._exception = (exc_type, exc_val, exc_tb)
            if self._debug and exc_type is not pywbem.CIMError:
                # if debugger is turned on, let it do the job
                return False
            if exc_type == pywbem.cim_http.AuthError:
                # do not handle Authentication
                return False
        return True

    def __contains__(self, key):
        return key in self._template_kwargs
    def __len__(self):
        return len(self._template_kwargs)
    def __getitem__(self, key):
        return self._template_kwargs[key]
    def __setitem__(self, key, val):
        self._template_kwargs[key] = val
        return val
    def __delitem__(self, key):
        return self._template_kwargs.pop(key)

def encode_reference(obj):
    """
    Encodes python object to base64 encoding (used for CIMInstanceNames,
    which can be passed as page parameters).
    @return compressed and encoded object.
    """
    # TODO: Consider using lib_util.Base64Encode, for portability.
    return base64.urlsafe_b64encode(
            zlib.compress(cPickle.dumps(obj, cPickle.HIGHEST_PROTOCOL)))

def val2str(value):
    """
    @return string representation of cim value
    """
    if value is None:
        return SafeString('<span class="null_val">Null</span>')
    if isinstance(value, pywbem.CIMDateTime):
        value = value.timedelta if value.is_interval else value.datetime
    if isinstance(value, datetime.datetime):
        value = value.strftime("%Y/%m/%d %H:%M:%S.%f")
    elif isinstance(value, datetime.date):
        value = value.strftime("%Y/%m/%d")
    elif isinstance(value, datetime.time):
        value = value.strftime("%H:%M:%S.%f")
    if isinstance(value, list):
        rval = '{'
        if value:
            for i in range(0, len(value)):
                item = value[i]
                if i > 0:
                    rval += ', '
                str_item = val2str(item)
                if type(item) in types.StringTypes:
                    str_item = '"' + str_item + '"'
                rval += str_item
        rval += '}'
        return rval
    return unicode(value)

def mapped_value2str(val, quals):
    """
    Similar to val2str, but this is used for valuemap qualifed values.
    """
    rval = ''
    if isinstance(val, list):
        rval += '{'
        value_list = val
    else:
        value_list = [val]
    valmap_qualifier = quals['valuemap'].value
    values_qualifier = quals['values'].value
    for i in value_list:
        if i is not value_list[0]:
            rval += ', '
        propstr = val2str(i)
        rval += propstr
        if propstr in valmap_qualifier:
            value_index = valmap_qualifier.index(propstr)
            if value_index < len(values_qualifier):
                rval += ' ('+values_qualifier[value_index]+')'
    if isinstance(val, list):
        rval += '}'
    return SafeString(rval)

