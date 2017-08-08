import ctypes
import ctypes_scanner
from ctypes_scanner import POINTER_T




# #define XIDDATASIZE 128         /* size in bytes */
# #define MAXGTRIDSIZE    64      /* maximum size in bytes of gtrid */
# #define MAXBQUALSIZE    64      /* maximum size in bytes of bqual */
# struct xid_t {
#     long        formatID;       /* format identifier */
#     long        gtrid_length;   /* value from 1 through 64 */
#     long        bqual_length;   /* value from 1 through 64 */
#     char        data[XIDDATASIZE];
# };
#
# #define RMNAMESZ 32             /* length of resource manager name, */
#                                 /* including the null terminator */
# #define MAXINFOSIZE 256         /* maximum size in bytes of xa_info strings, */
#                                 /* including the null terminator */
# struct xa_switch_t {
#     char name[RMNAMESZ];        /* name of resource manager */
#     long flags;                 /* resource manager specific options */
#     long version;               /* must be 0 */
#
#     int  (*xa_open_entry)(char *, int, long);   /*xa_open function pointer*/
#     int  (*xa_close_entry)(char *, int, long);  /*xa_close function pointer*/
#     int  (*xa_start_entry)(XID *, int, long);   /*xa_start function pointer*/
#     int  (*xa_end_entry)(XID *, int, long);     /*xa_end function pointer*/
#     int  (*xa_rollback_entry)(XID *, int, long);
#                                                /*xa_rollback function pointer*/
#     int  (*xa_prepare_entry)(XID *, int, long); /*xa_prepare function pointer*/
#     int  (*xa_commit_entry)(XID *, int, long);  /*xa_commit function pointer*/
#     int  (*xa_recover_entry)(XID *, long, int, long);
#                                                 /*xa_recover function pointer*/
#     int  (*xa_forget_entry)(XID *, int, long);  /*xa_forget function pointer*/
#     int  (*xa_complete_entry)(int *, int *, int, long);
# };



lstStructs = [ ]
ctypes_scanner.DoAll(lstStructs)