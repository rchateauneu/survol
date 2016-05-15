#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Inspired by public domain code scripts/readelf.py :
# A clone of 'readelf' in Python, based on the pyelftools library
# Eli Bendersky (eliben@gmail.com)
#-------------------------------------------------------------------------------
import os, sys
from optparse import OptionParser
import string

import demangler

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')


from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.common.py3compat import (
        ifilter, byte2int, bytes2str, itervalues, str2bytes)
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.segments import InterpSegment, NoteSegment
from elftools.elf.sections import SymbolTableSection
from elftools.elf.gnuversions import (
    GNUVerSymSection, GNUVerDefSection,
    GNUVerNeedSection,
    )
from elftools.elf.relocation import RelocationSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_ver_flags, describe_note
    )
from elftools.elf.constants import E_FLAGS
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.descriptions import (
    describe_reg_name, describe_attr_value, set_global_machine_arch,
    describe_CFI_instructions, describe_CFI_register_rule,
    describe_CFI_CFA_rule,
    )
from elftools.dwarf.constants import (
    DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
from elftools.dwarf.callframe import CIE, FDE

################################################################################


# top_level_split( "aa::bb<cc::dd>::ee","::","<",">")
def top_level_split(instr,delim,bracket_open,bracket_close):
    parts = []
    bracket_level = 0
    current = ""
    # sys.stdout.write("str=%s delim=%s\n" % ( instr, delim ) )
    # trick to remove special-case of trailing chars
    lenInstr = len(instr)
    idx = 0
    while idx < lenInstr:
        # sys.stdout.write("startswith=%d idx=%d cur=%s\n" % ( instr.startswith( delim, idx ), idx, current ))
        if instr.startswith( delim, idx ) and bracket_level == 0:
            if current:
                parts.append(current)
            current = ""
            idx += len(delim)
        else:
            ch = instr[idx]
            if ch == bracket_open:
                bracket_level += 1
            elif ch == bracket_close:
                bracket_level -= 1
            current += ch
            idx += 1
    if current:
        parts.append(current)
    if not parts:
        parts = [""]
    # sys.stdout.write("str=%s parts=%s\n" % ( instr, str(parts) ) )
    return parts

################################################################################

scalarTypes = set( [
    "bool",
    "short",
    "unsigned short",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "long long",
    "unsigned long long",
    "float",
    "double", ]
    )

# unsigned short const*
# xercesc_3_1::ValueStore const*
# xercesc_3_1::RefVectorOf<xercesc_3_1::XMLAttr> const&
# bool
# xercesc_3_1::RefHash2KeysTableBucketElem<xercesc_3_1::ValueVectorOf<xercesc_3_1::SchemaElementDecl*> >**

def ExtractClassesFromType(lstCls, cls):
    if not cls:
        return
    while cls[-1] in "*&":
        cls = cls[:-1]

    if cls.endswith(" const"):
        cls = cls[:-6]

    # This is just for the most common cases because it cannot eliminate typedefs.
    if cls in scalarTypes:
        return

    lstCls.append( cls )

    # There might also be template parameters.
    ExtractTemplatedClassesFromToken( lstCls, cls )

# There might be several template parameters.
# XMLEnumerator<xercesc_3_1::FieldValueMap>
def ExtractTemplatedClassesFromToken(lstCls, cls):
    bracketFirst = cls.find("<")
    if bracketFirst <= 0:
        return None
    bracketLast = cls.rfind(">")
    strTmplArgs = cls[ bracketFirst + 1: bracketLast ]

    # Beware : Add other delimiters if template parameters contain "()"
    # such as function pointers.
    tmplArgs = top_level_split( strTmplArgs, ",", "<", ">" )
    for tmplArg in tmplArgs:
        ExtractClassesFromType( lstCls, tmplArg )


################################################################################

class ElfSym:
    def __init__(self, Type, Bind, Vis, Ndx, Vers, Name ):
        # sys.stdout.write('t=%-7s b=%-6s v=%-7s n=%4s V=%s N=%s\n' % ( Type, Bind, Vis, Ndx, Vers, Name ) )
        self.m_type = Type
        self.m_bind = Bind
        self.m_vis  = Vis
        self.m_ndx  = Ndx
        self.m_vers = Vers
        self.m_name = Name

        firstPar = self.m_name.find("(")
        if firstPar < 0:
            # This is a singleton.
            fulNam = self.m_name
            self.m_args = None # Different from zero arguments.
        else:
            fulNam = self.m_name[:firstPar]
            # There might be ") const" at the end.
            if self.m_name.endswith(" const"):
                # TODO: We are sure that the last token is a class, not a namespace.
                endIdx = -7
            else:
                endIdx = -1
            argsNoParenth = self.m_name[firstPar+1:endIdx]
            if argsNoParenth == "":
                self.m_args = [] # Zero argument.
            else:
                # TODO: Arguments cannot be namespaces. Template parameters also.
                self.m_args = [ arg.strip() for arg in top_level_split(argsNoParenth,",","<",">") ]
                
        self.m_splt = top_level_split( fulNam, "::", "<", ">" )
        self.m_short_nam = self.m_splt[-1]

    # Returns 

    # Retourne les classes passees comme arguments.
    def GetArgsClasses(self):
        # Maybe this is a singleton, not a method.
        lstClasses = []
        if self.m_args:
            for arg in self.m_args:
                ExtractClassesFromType(lstClasses,arg)
        return lstClasses

    # Classes instantiating this class and nesting classes.
    # Even the method might be templatised.
    # Not always needed because if the class can be instantiated,
    # its symbols might be listed in the ELF file also.
    def GetTmplClasses(self):
        lstClasses = []
        for cls in self.m_splt:
            # Each string is a namespace, a class or a method.
            ExtractTemplatedClassesFromToken(lstClasses,cls)
        return lstClasses

    def CalcNS(self,setClasses):
        numSplt = len(self.m_splt)
        # C est un peu incoherent car pour retirer le namespace 
        # d une classe connue, on prend le prefixe qui n est pas
        # une classe connue.
        # En revanche; si tout le nom est inconnu, on suppose
        # que c est integralement une classe.
	for idx in range( 0, numSplt ):
            # TODO: Vraiment TRES LENT ....
            tmp = "::".join(self.m_splt[ 0: idx ])
            # print("tmp TEST:%s" %tmp)
            if tmp in setClasses :
                # print("tmp OK:%s" %tmp)
                if idx == 0:
                    self.m_namespace = []
                    self.m_class = self.m_splt[: -1]
                else:
                    self.m_namespace = self.m_splt[ : idx - 1 ]
                    self.m_class = self.m_splt[ idx - 1 : -1]
                break
        else:
            self.m_namespace = []
            self.m_class = self.m_splt
        #print(str(sym))
        #print("ns=%s cl=%s sp=%s" % ( str(sym.m_namespace), str(sym.m_class), str(sym.m_splt) ) )
        #print("")

    # xercesc_3_1::NameIdPool<xercesc_3_1::DTDElementDecl>::~NameIdPool()
    def IsDestructor(self):
        return self.m_short_nam and self.m_short_nam[0] == "~"

    # xercesc_3_1::NameIdPool<xercesc_3_1::DTDElementDecl>::NameIdPool(unsigned long, unsigned long, xercesc_3_1::MemoryManager*)
    def IsConstructor(self):
        if len(self.m_splt) <= 1:
            return False
        classNam = self.m_splt[-2]

        idxBracket = classNam.find("<")
        if idxBracket < 0:
            # This is not a template class.
            if self.m_short_nam == classNam:
                return True
        else:
            # If this is a template class.
            classNoTemplate = classNam[ : idxBracket ]
            if self.m_short_nam == classNoTemplate:
                return True

        return False


    def __str__(self):
        hed = "::".join( self.m_splt[:-1] )

        # return 't=%-7s b=%-6s v=%-7s n=%4s V=%s N=%s H=%s E=%s\n' % ( self.m_type, self.m_bind, self.m_vis, self.m_ndx, self.m_vers, self.m_name, hed, nam )
        # return 'NS=%s CL=%s FU=%s A=%s' % ( str(self.m_namespace), str(self.m_class), self.m_short_nam, str(self.m_args) )
        return 't=%-7s b=%-6s v=%-7s NS=%s CL=%s FU=%s A=%s' % ( self.m_type, self.m_bind, self.m_vis, str(self.m_namespace), str(self.m_class), self.m_short_nam, str(self.m_args) )

def indexStartsWith( str, prefix ):
    l = len(prefix)
    if str.startswith( prefix ):
        return str[l:]
    else:
        return None 

class ReadElf(object):
    """ display_* methods are used to emit output into the output stream
    """
    def __init__(self, file, output):
        """ file:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.elffile = ELFFile(file)
        self.output = output

        # Lazily initialized if a debug dump is requested
        self._dwarfinfo = None

        self._versioninfo = None

    def display_symbol_tables(self):
        """ Display the symbol tables contained in the file
        """
        self._init_versioninfo()

        listSyms = []
        setClasses = set()

        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue

            for nsym, symbol in enumerate(section.iter_symbols()):

                version_info = ''
                # readelf doesn't display version info for Solaris versioning
                if (section['sh_type'] == 'SHT_DYNSYM' and
                        self._versioninfo['type'] == 'GNU'):
                    version = self._symbol_version(nsym)
                    if (version['name'] != symbol.name and
                        version['index'] not in ('VER_NDX_LOCAL',
                                                 'VER_NDX_GLOBAL')):
                        if version['filename']:
                            # external symbol
                            version_info = '@%(name)s (%(index)i)' % version
                        else:
                            # internal symbol
                            if version['hidden']:
                                version_info = '@%(name)s' % version
                            else:
                                version_info = '@@%(name)s' % version

                demang = demangler.demangle(symbol.name)

                nnn = indexStartsWith( demang, "vtable for " )
                if nnn:
                    setClasses.add( nnn )
                    continue

                nnn = indexStartsWith( demang, "typeinfo name for " )
                if nnn:
                    setClasses.add( nnn )
                    continue

                nnn = indexStartsWith( demang, "typeinfo for " )
                if nnn:
                    setClasses.add( nnn )
                    continue

                nnn = indexStartsWith( demang, "non-virtual thunk to " )
                if nnn:
                    # No need to duplicate the symbol.
                    # demang = nnn
                    continue
                    
                sym = ElfSym(
                    describe_symbol_type(symbol['st_info']['type']),
                    describe_symbol_bind(symbol['st_info']['bind']),
                    describe_symbol_visibility(symbol['st_other']['visibility']),
                    describe_symbol_shndx(symbol['st_shndx']),
                    version_info,
                    demang )

                listSyms.append( sym )

        return ( listSyms, setClasses )

    def display_notes(self):
        """ Display the notes contained in the file
        """
        result = []
        sys.stdout.write("\n")
        for segment in self.elffile.iter_segments():
            if isinstance(segment, NoteSegment):
                for note in segment.iter_notes():
                    pairNote = ( note['n_name'], describe_note(note))
                    sys.stdout.write('n=%s d=%s\n' % pairNote )
                    result.append( pairNote )
        return result
        

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True):
        """ Format an address into a hexadecimal string.

            fieldsize:
                Size of the hexadecimal field (with leading zeros to fit the
                address into. For example with fieldsize=8, the format will
                be %08x
                If None, the minimal required field size will be used.

            fullhex:
                If True, override fieldsize to set it to the maximal size
                needed for the elfclass

            lead0x:
                If True, leading 0x is added

            alternate:
                If True, override lead0x to emulate the alternate
                hexadecimal form specified in format string with the #
                character: only non-zero values are prefixed with 0x.
                This form is used by readelf.
        """

        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def _init_versioninfo(self):
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """
        if self._versioninfo is not None:
            return

        self._versioninfo = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'

    def _symbol_version(self, nsym):
        """ Return a dict containing information on the symbol
                   or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store wether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version

def CalcNamspaces( setClasses, listSyms ):
    for sym in listSyms:
        sym.CalcNS(setClasses)


def GetClassesFromCTorDTor( listSyms ):
    setMoreClasses = set()
    for sym in listSyms:
        # Destructor or constructor.
        if sym.IsConstructor() or sym.IsDestructor():
            cls = "::".join( sym.m_splt[:-1] )
            setMoreClasses.add( cls )
            # Debugging purpose only should never happen.
            if cls == 'xercesc_3_1':
                print("ATTENTION:%s" %   "::".join( sym.m_splt ) )
                print("ATTENTION:%s" %   sym.m_name )
                exit(0)
            continue

        # In the ordered list of classes or namespaces,
        # if a string is a template, then this prefix and what
        # follows, can only be class names.
        isCls = False
        for idx in range( len(sym.m_splt) - 1 ):
            if not isCls:
                if sym.m_splt[idx].find("<") >= 0:
                    isCls = True
                else:
                    continue
            cls = "::".join( sym.m_splt[ 0 : idx + 1 ] )
            print("INTERMEDIATE:%s"%cls)
            setMoreClasses.add( cls )

        # Classes passed as parameters.
        argsClasses = sym.GetArgsClasses()
        setMoreClasses.update( argsClasses )

        tmplClasses = sym.GetTmplClasses()
        setMoreClasses.update( tmplClasses )
            

        # A template parameter cannot be a namespace.

    return setMoreClasses

