# ---------- Forwarded message ----------
# Date: Wed, Mar 29, 2017 at 2:07 PM
# Subject: CLR status / Idees Survol
# To: "remi.chateauneu@gmail.com" <remi.chateauneu@gmail.com>
#
# http://stackoverflow.com/questions/2080046/how-to-check-if-a-program-is-using-net
#
# Use the CLR COM interfaces ICorPublish and ICorPublishProcess. The easiest way to do this from C# is to borrow some code from SharpDevelop's debugger, and do the following:
#
# ICorPublish publish = new ICorPublish();
#
# ICorPublishProcess process;
#
# process = publish.GetProcess(PidToCheck);
#
# if (process == null || !process.IsManaged)
# {
#     // Not managed.
# }
# else
# {
#     // Managed.
# }
#
# EnumProcesses Method
#
# Gets an ICorPublishProcessEnum instance that contains the managed processes running on this computer.
#
# https://en.wikipedia.org/wiki/Application_domain
#
# ICorPublishAppDomain::GetName Method
#
# Programmatically you'd get the starting image name using Win32 API like NtQueryInformationProcess, or in .Net use System.Diagnostics.Process.GetProcesses() and read Process.StartInfo.FileName.
# Then open and decode the PE headers of that image using details prescribed in the MSDN article below:
# http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
# Caveats: will only detect .NET built assemblies e.g. won't detect Win32 EXEs dynamically hosting CLR using CorHost APIs.
#
# pythonnet
# https://pypi.python.org/pypi/pythonnet/2.2.1
# https://msdn.microsoft.com/en-us/library/f7dy01k1(v=vs.110).aspx
#
# Ildasm.exe
#
# This also works with .net exe, dll,obj,lib. Proposer ca pour les exe et les dlls et tester si .net bien entendu.
#
# Dans le message d erreur il faut dire si ildasm est accessible ou pas, sinon il faudra debugger pour le faire fonctionner.
#
# /html
#
# Produces output in HTML format. Valid with the /output option only.
# // Classes defined in this module:
#
# //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# // Class WebApiConfig                   (public) (abstract) (auto) (ansi) (sealed)
# // Class Configuration                  (public) (auto) (ansi)
# // Class AuthenticationController       (public) (auto) (ansi)
#
# /noil /class /forward /meta/nobar
#
# /ITEM=<class>[::<method>[(<sig>)]  Disassemble the specified item only
#
