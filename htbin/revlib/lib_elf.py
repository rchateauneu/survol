#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Inspired by public domain code scripts/readelf.py :
# A clone of 'readelf' in Python, based on the pyelftools library
# Eli Bendersky (eliben@gmail.com)
#-------------------------------------------------------------------------------
import os
import sys
# from optparse import OptionParser
import string
import demangler
import lib_symbol

# For running from development directory. It should take precedence over the
# installed pyelftools.
# sys.path.insert(0, '.')


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

# xercesc_3_1::SAXParser::startElement(xercesc_3_1::XMLElementDecl const&, unsigned int, unsigned short const*, xercesc_3_1::RefVectorOf<xercesc_3_1::XMLAttr> const&, unsigned long, bool, bool)
# t=FUNC	b=GLOBAL v=DEFAULT NS=['xercesc_3_1'] CL=['SAXParser'] FU=startElement A=['xercesc_3_1::XMLElementDecl const&', 'unsigned int', 'unsigned short const*', 'xercesc_3_1::RefVectorOf<xercesc_3_1::XMLAttr> const&', 'unsigned long', 'bool', 'bool']
#
# On veut eviter de reparser le fichier ELF. On passe le symbol en entier, demangle.
# En plus, on passe optionnellement le namespace (Car l extraire, de facon incertaine, exige de 
# connaitre en plus le reste du fichier ELF. ON assimile namespace et classe !!!
# On passe aussi, optionnellement, les autres parametres (Et encore, on s'en fiche).
# Il faut reconstruire un ElfSym uniquement avec le symbole.


class ElfSym:
	def __init__(self, NamDemang, NamRaw, Type=None, Bind=None, Vis=None, Ndx=None, Vers=None ):
		# sys.stdout.write('t=%-7s b=%-6s v=%-7s n=%4s V=%s N=%s\n' % ( Type, Bind, Vis, Ndx, Vers, Name ) )
		self.m_type        = Type
		self.m_bind        = Bind
		self.m_vis         = Vis
		self.m_ndx         = Ndx
		self.m_vers        = Vers
		self.m_name_demang = NamDemang
		self.m_name_mangle = NamRaw

		( fulNam, self.m_args ) = lib_symbol.SymToArgs( self.m_name_demang )

		self.m_splt = lib_symbol.top_level_split( fulNam, "::", "<", ">" )
		self.m_short_nam = self.m_splt[-1]

	# Returns list of classes passed as arguments.
	def GetArgsClasses(self):
		# Maybe this is a singleton, not a method.
		lstClasses = []
		if self.m_args:
			for arg in self.m_args:
				lib_symbol.ExtractClassesFromType(lstClasses,arg)
		return lstClasses

	# Classes instantiating this class and nesting classes.
	# Even the method might be templatised.
	# Not always needed because if the class can be instantiated,
	# its symbols might be listed in the ELF file also.
	def GetTmplClasses(self):
		lstClasses = []
		for cls in self.m_splt:
			# Each string is a namespace, a class or a method.
			lib_symbol.ExtractTemplatedClassesFromToken(lstClasses,cls)
		return lstClasses

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
		return 't=%-7s b=%-6s v=%-7s FU=%s A=%s' % ( self.m_type, self.m_bind, self.m_vis, self.m_short_nam, str(self.m_args) )

def indexStartsWith( str, prefix ):
	l = len(prefix)
	if str.startswith( prefix ):
		return str[l:]
	else:
		return None 

class ReadElf(object):
	def __init__(self, fileName):
		file = open(fileName, 'rb')

		self.elffile = ELFFile(file)

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

				# Related to virtual inheritance.
				# http://stackoverflow.com/questions/6258559/what-is-the-vtt-for-a-class
				nnn = indexStartsWith( demang, "VTT for " )
				# TODO: Use it to build class hierarchy ???
				if nnn:
					continue
					
				sym = ElfSym(
					demang,
					symbol.name,
					describe_symbol_type(symbol['st_info']['type']),
					describe_symbol_bind(symbol['st_info']['bind']),
					describe_symbol_visibility(symbol['st_other']['visibility']),
					describe_symbol_shndx(symbol['st_shndx']),
					version_info )

				listSyms.append( sym )

		return ( listSyms, setClasses )

	def display_notes(self):
		""" Display the notes contained in the file
		"""
		result = []
		for segment in self.elffile.iter_segments():
			if isinstance(segment, NoteSegment):
				for note in segment.iter_notes():
					pairNote = ( note['n_name'], describe_note(note))
					# sys.stdout.write('n=%s d=%s\n' % pairNote )
					result.append( pairNote )
		return result
		
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

# TODO: Not used yet !!!
def GetClassesFromCTorDTor( listSyms ):
	setMoreClasses = set()
	for sym in listSyms:
		# Destructor or constructor.
		if sym.IsConstructor() or sym.IsDestructor():
			cls = "::".join( sym.m_splt[:-1] )
			setMoreClasses.add( cls )
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
			setMoreClasses.add( cls )

		# Classes passed as parameters.
		argsClasses = sym.GetArgsClasses()
		setMoreClasses.update( argsClasses )

		tmplClasses = sym.GetTmplClasses()
		setMoreClasses.update( tmplClasses )
			

		# A template parameter cannot be a namespace.

	return setMoreClasses

