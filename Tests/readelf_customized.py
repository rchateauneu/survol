#!/usr/bin/env python

import sys
import lib_elf

def main(stream=None):

    if len(sys.argv) == 1:
        fil = "/usr/lib64/libxerces-c-3.1.so"
    else:
        fil = sys.argv[1]
    with open(fil, 'rb') as file:
        try:
            readelf = lib_elf.ReadElf(file, stream or sys.stdout)
            listNotes = readelf.display_notes()
            for pr in listNotes:
                sys.stdout.write("%s %s\n" % pr )
            sys.stdout.write("\n")

            listSyms, setClasses = readelf.display_symbol_tables()

            setMoreClasses = lib_elf.GetClassesFromCTorDTor(listSyms)

            unionClasses = setClasses.union( setMoreClasses )

            # setNamespaces = GetNamespacesHeuristics( unionClasses )
            # PROBLEM: What is the difference between a namespace
            # and a non-virtual class with static methods and members only ???
            # ALSO: The symbol name gives no information about the return type
            # and the object parameter whose presence would indicate with certainty
            # a class as opposed to a namespace.
            lib_elf.CalcNamspaces( unionClasses, listSyms )
            for sm in listSyms:
                sys.stdout.write("%s\n" % sm.m_name )
                sys.stdout.write("%s\n" % str(sm) )
		sys.stdout.write("\n")

            print(str(sorted(setClasses)))
            print("")
            print(str(sorted(setMoreClasses)))
            print("")
            print(str(sorted(unionClasses)))

        except ELFError as ex:
            sys.stderr.write('ELF error: %s\n' % ex)
            sys.exit(1)


#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    #profile_main()
