# On l implemente en Mono appele par du Python car de toute facon Mono est necessaire.
#
# (1) The debugger agent is a module inside the mono runtime which offers debugging services to client programs.
# http://www.mono-project.com/docs/advanced/runtime/docs/soft-debugger/
# The client library is a C# assembly which uses the wire protocol to communicate
# with the debugger agent running inside the mono runtime.
