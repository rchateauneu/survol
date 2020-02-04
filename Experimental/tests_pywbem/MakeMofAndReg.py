import pywbem
import pywbem.cim_provider2

import sys

# Ca fabrique les stubs de code a partir du mof une fois qu'il a ete enregistre.
# Notons que c'est du pywbem, pas du LMI.
conn = pywbem.WBEMConnection("https://192.168.1.88", ("pegasus", "toto"))

# Si URL="192.168.1.88", alors on a:
# UnboundLocalError: local variable 'url_' referenced before assignment

# UnboundLocalError: local variable 'url_' referenced before assignment
# cl = conn.GetClass("TUT_UnixProcess")

# clsnam="CIM_UnixProcess"
clsnam="PG_UnixProcess"

cl = conn.GetClass(clsnam)
(provider, registration) = pywbem.cim_provider2.codegen(cl)

filpro = open(clsnam + ".mof", "w")
filpro.write( provider )
filpro.close()

filreg = open(clsnam + ".reg", "w")
filreg.write( registration )
filreg.close()
