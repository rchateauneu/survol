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
Defines functions for obtaining information from pywbem objects.

YAWN represents CIM objects as dictionaries. These functions make the
transformation to them.
"""

import pywbem
import yawn_render
import yawn_util

def get_all_hierarchy(conn, class_name):
    """
    Used only AssociatedClases.
    TODO: make it part of on_AssociatedClasses
    """
    hierarchy = []

    hierarchy.append(class_name)
    cname = class_name
    while cname != None:
        subklass = conn.GetClass(cname, LocalOnly=False,
                IncludeQualifiers=True)
        if subklass.superclass != None:
            cname = subklass.superclass
            hierarchy.append(cname)
        else:
            cname = None
    return hierarchy

def _get_prop_value(prop, inst=None):
    """
    @param prop is either pywbem.CIMParameter or pywbem.CIMProperty
    @inst can be pywbem.CIMInstance or pywbem.CIMInstanceName
    @return value of property depending on supplied parameters
    """
    if isinstance(prop, pywbem.CIMParameter):
        return prop.value
    if inst is not None:
        if isinstance(inst, pywbem.CIMInstance):
            if prop.name in inst.properties:
                return inst.properties[prop.name].value
        else:
            if prop.name in inst:
                return inst[prop.name]
    if prop.value is not None:
        return prop.value
    return None

def _get_prop_type(prop, inst=None):
    """
    @param prop is either pywbem.CIMParameter or pywbem.CIMProperty
    @inst can be pywbem.CIMInstance or pywbem.CIMInstanceName
    @return type of property, which can be:
           dictionary representing reference to object name
             containg ( 'className', 'ns' ) keys
           string representing any other type
    """
    value = _get_prop_value(prop, inst)
    res = '<UNKNOWN>'
    if (   prop.reference_class is None
       and (  prop.type != 'reference'
           or not isinstance(value, pywbem.CIMInstanceName))):
        res = prop.type
    else:
        res = {'className' : None }
        if prop.reference_class is not None:
            res['className'] = prop.reference_class
        else:
            if isinstance(value, list):
                value = value[0] if len(value) else None
            if isinstance(value, pywbem.CIMInstanceName):
                res['className'] = value.classname
                res['ns'] = value.namespace
    return res

def _get_default_attributes_dict(name, **kwargs):
    """
    @param kwargs any initial item values can be passed in this
    argument
    @return dictionary with default properties of any attribute
    of CIM class, instance or instance name
    """
    if not isinstance(name, basestring):
        raise TypeError("name must be string")
    res = { 'name'         : name
          , 'is_deprecated': False
          # whether the item is declared be current class or
          # by some parent class
          , 'is_local'     : False
          # class, that defines this item (may be None)
          , 'class_origin' : None
          , 'is_key'       : False
          , 'is_array'     : False
          , 'is_method'    : False
          , 'is_required'  : False
          , 'is_valuemap'  : False
          , 'valuemap'     : []
          , 'values'       : {}
          , 'array_size'   : None
          , 'value'        : None
          , 'value_orig'   : None
          # only valid for method
          , 'args'         : []
          , 'type'         : "<Unknown>"
          # all less interesting qualifiers sorted by name
          , 'qualifiers'   : []
          }
    res.update(kwargs)
    return res

def _get_property_details(prop, inst=None):
    """
    @param prop is either CIMProperty or CIMParameter
    @param inst is either CIMInstance or CIMInstanceName
    @return dictionary describing property
    """
    if not isinstance(prop, (pywbem.CIMProperty, pywbem.CIMParameter)):
        raise TypeError('prop must be either CIMProperty or CIMParameter')
    if (   inst is not None
       and not isinstance(inst, pywbem.CIMInstance)
       and not isinstance(inst, pywbem.CIMInstanceName)):
        raise TypeError('inst must be one of: CIMInstance,'
               ' CIMInstanceName, None')
    value = _get_prop_value(prop, inst)

    res = _get_default_attributes_dict(prop.name,
            is_deprecated = prop.qualifiers.has_key('deprecated'),
            is_required   = prop.qualifiers.has_key('required'),
            is_valuemap   = prop.qualifiers.has_key('valuemap'),
            is_key     = prop.qualifiers.has_key('key'),
            type       = _get_prop_type(prop, inst),
            value_orig = value)

    if prop.is_array:
        res['is_array'] = prop.is_array
        res['array_size'] = prop.array_size

    if value is not None:
        if (   prop.qualifiers.has_key('values')
           and prop.qualifiers.has_key('valuemap')):
            res['value'] = yawn_render.mapped_value2str(value, prop.qualifiers)
        elif prop.reference_class is not None:
            res['value'] = value
        else:
            res['value'] = yawn_render.val2str(value)

    if prop.qualifiers.has_key('valuemap'):
        res['is_valuemap'] = True
        valmap_quals = prop.qualifiers['valuemap'].value
        values_quals = None
        if prop.qualifiers.has_key('values'):
            values_quals = prop.qualifiers['values'].value
        for ivq, val in enumerate(valmap_quals):
            try:
                pywbem.tocimobj(prop.type, val)
            except Exception:
                # skip valuemap items that aren't valid values
                # such as the numeric ranges for DMTF Reserved and whatnot
                continue
            res['valuemap'].append(val)
            if values_quals and ivq < len(values_quals):
                res['values'][val] = [values_quals[ivq]]
            else:
                res['values'][val] = None

    if isinstance(prop, pywbem.CIMParameter):
        res['out'] = (   prop.qualifiers.has_key('out')
                     and prop.qualifiers['out'].value)
        # consider parameter as input if IN qualifier is missing and
        # it is not an output parameter
        res['in'] = (  (   prop.qualifiers.has_key('in')
                       and prop.qualifiers['in'].value)
                    or (   not prop.qualifiers.has_key
                       and not res['out']))
    return res

def get_class_item_details(class_name, item, inst=None):
    """
    @param item can be one of {
        CIMProperty, CIMMethod, CIMParameter }
    @param inst provides some additional info (if given)
    """
    if not isinstance(class_name, basestring):
        raise TypeError('class_name must be a string')
    if not isinstance(item, (pywbem.CIMProperty, pywbem.CIMMethod,
            pywbem.CIMParameter)):
        raise TypeError('item must be either CIMProperty,'
                ' CIMParameter or CIMMethod')
    if (   inst is not None
       and not isinstance(inst, (pywbem.CIMInstanceName, pywbem.CIMInstance))):
        raise TypeError('inst must be one of CIMInstanceName'
            ', CIMInstance or None')

    res = _get_default_attributes_dict(item.name,
            is_deprecated = item.qualifiers.has_key('deprecated'),
            is_method     = isinstance(item, pywbem.CIMMethod),
            is_required   = item.qualifiers.has_key('required'),
            is_valuemap   = item.qualifiers.has_key('valuemap'))

    if isinstance(item, (pywbem.CIMProperty, pywbem.CIMParameter)):
        res.update(_get_property_details(item, inst))
    elif isinstance(item, pywbem.CIMMethod): # CIMMethod
        res['type'] = item.return_type
        args = res['args']
        for parameter in item.parameters.values():
            args.append(get_class_item_details(class_name, parameter))

    if hasattr(item, 'class_origin'):
        res['is_local'] = item.class_origin == class_name
        res['class_origin'] = item.class_origin
    if item.qualifiers.has_key('description'):
        res['description'] = item.qualifiers['description'].value
    else:
        res['description'] = None
    for qualifier in sorted(item.qualifiers.values(), key=lambda v: v.name):
        if qualifier.name.lower() in (
                'description', 'key', 'required'):
            continue
        res['qualifiers'].append(
                (qualifier.name, yawn_render.val2str(qualifier.value)))

    return res

def get_class_props(klass=None, inst=None, include_all=False, keys_only=False):
    """
    @param inst may be CIMInstance
        if given and include_all == False, then only properties
        defined by provider will be returned
        if None, then all properties declared by klass will be returned
    @param include_all if True, then all properties declared by klass
        and all defined by given instance will be returned
    @param keys_only if True, then only key properties are returned
    @note properties declared by klass != propertied defined be instance,
        that's why include_all flag is provided
    @note qualifiers declared be class override those provided by instance
    @return props: [ { 'name'        : name
                     , 'type'        : type
                     , 'value'       : value
                     , 'description' : description
                     , 'is_key'      : bool
                     , 'is_required' : bool
                     , 'is_array'    : bool
                     , 'qualifiers'  : [(name, value), ...]
                     }
                   , ...
                   ]
    if property is not in schema, then type is None and the rest
        of fields are undefined
    if type of property is reference, then:
        type  = {ns : namespace, className: class_name}
        value = object_path object
    """
    if klass is not None and not isinstance(klass, pywbem.CIMClass):
        raise TypeError('klass must be object of CIMClass')
    if (  inst is not None
       and not isinstance(inst, (pywbem.CIMInstance, pywbem.CIMInstanceName))):
        raise TypeError('inst must be either CIMInstance,'
        ' CIMInstanceName or None')
    if klass is None and inst is None:
        raise ValueError('klass or inst argument must be given')

    keys = set()
    if inst is not None:
        keys = set(inst.keys())
        if include_all and klass is not None:
            keys.update(set(klass.properties.keys()))
    else:
        keys = klass.properties.keys()
    keys = sorted(keys, yawn_util.cmp_pnames(klass))

    props = []
    for prop_name in keys:
        iprop = None
        if (  isinstance(inst, pywbem.CIMInstance)
           and prop_name in inst.properties):
            iprop = inst.properties[prop_name]
            if (  keys_only
               and not iprop.qualifiers.has_key('key')
               and not prop_name in inst.path):
                continue
        cprop = (  klass.properties[prop_name]
                if klass and klass.properties.has_key(prop_name) else None)
        if keys_only and cprop and not cprop.qualifiers.has_key('key'):
            continue
        if cprop is not None:
            item = get_class_item_details(klass.classname, cprop, inst)
        elif iprop is not None:
            item = _get_property_details(iprop, inst)
        elif isinstance(inst, pywbem.CIMInstanceName):
            item = _get_default_attributes_dict(prop_name)
            if prop_name in inst:
                value = inst[prop_name]
                item['is_key']     = True
                item['is_array']   = isinstance(inst[prop_name], list)
                item['value']      = value
                item['value_orig'] = value
                if isinstance(value, pywbem.CIMInstanceName):
                    item['type'] = { 'className' : value.classname
                                   , 'ns'        : value.namespace }
        else:
            item = _get_default_attributes_dict(prop_name)
        props.append(item)
    return props

def get_class_methods(klass):
    """
    @return { 'name' : method_name
            , 'args' : arguments (just names)
            }
    """
    if not isinstance(klass, pywbem.CIMClass):
        raise TypeError('klass must be a CIMClass object')
    methods = []
    for method in klass.methods.values():
        methods.append((method.name, method.parameters.keys()))
    return methods

def get_inst_info(inst, klass=None, include_all=False, keys_only=False):
    """
    @return { 'className'  : class_name
            , 'ns'         : namespace
            , 'path'       : path
            , 'props'      : [ p1dict, ... ]
            , 'methods'    : [ m1dict, ... ]
            , ...
            }
    """
    pth = inst if isinstance(inst, pywbem.CIMInstanceName) else inst.path
    info = { 'className' : pth.classname
           , 'ns'        : pth.namespace
           , 'host'      : pth.host
           , 'props'     : get_class_props(klass, inst,
               include_all=include_all, keys_only=keys_only)
           , 'path'      : pth
           , 'methods'   : []
           }
    if klass is not None:
        info['methods'] = get_class_methods(klass)
    return info

def get_method_params(class_name, cimmethod):
    """
    @return (in_params, out_params)
    where both are list of dictionaries
    """
    in_params  = []
    out_params = []

    if not isinstance(cimmethod, pywbem.CIMMethod):
        raise TypeError('cimmethod must be instance of pywbem.CIMMethod')
    for param in cimmethod.parameters.values():
        details = get_class_item_details(class_name, param)
        if details['in']:
            in_params.append(details)
        if details['out']:
            out_params.append(details)

    return (in_params, out_params)

