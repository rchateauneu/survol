import ctypes
import ctypes_scanner
from ctypes_scanner import POINTER_T

# MQ
# http://usuaris.tinet.cat/jpmiguez/mqv8/cmqc.h


 # struct tagMQAIR {
 #   MQCHAR4    StrucId;                /* Structure identifier */
 #   MQLONG     Version;                /* Structure version number */
 #   MQLONG     AuthInfoType;           /* Type of authentication */
 #                                      /* information */
 #   MQCHAR     AuthInfoConnName[264];  /* Connection name of CRL LDAP */
 #                                      /* server */
 #   PMQCHAR    LDAPUserNamePtr;        /* Address of LDAP user name */
 #   MQLONG     LDAPUserNameOffset;     /* Offset of LDAP user name */
 #                                      /* from start of MQAIR */
 #                                      /* structure */
 #   MQLONG     LDAPUserNameLength;     /* Length of LDAP user name */
 #   MQCHAR32   LDAPPassword;           /* Password to access LDAP */
 #                                      /* server */
 #   /* Ver:1 */
 #   MQCHAR256  OCSPResponderURL;       /* URL of the OCSP responder */
 #   /* Ver:2 */
 # };

 # struct tagMQCNO {
 #   MQCHAR4    StrucId;              /* Structure identifier */
 #   MQLONG     Version;              /* Structure version number */
 #   MQLONG     Options;              /* Options that control the */
 #                                    /* action of MQCONNX */
 #   /* Ver:1 */
 #   MQLONG     ClientConnOffset;     /* Offset of MQCD structure for */
 #                                    /* client connection */
 #   MQPTR      ClientConnPtr;        /* Address of MQCD structure for */
 #                                    /* client connection */
 #   /* Ver:2 */
 #   MQBYTE128  ConnTag;              /* Queue-manager connection tag */
 #   /* Ver:3 */
 #   PMQSCO     SSLConfigPtr;         /* Address of MQSCO structure for */
 #                                    /* client connection */
 #   MQLONG     SSLConfigOffset;      /* Offset of MQSCO structure for */
 #                                    /* client connection */
 #   /* Ver:4 */
 #   MQBYTE24   ConnectionId;         /* Unique Connection Identifier */
 #   MQLONG     SecurityParmsOffset;  /* Offset of MQCSP structure */
 #   PMQCSP     SecurityParmsPtr;     /* Address of MQCSP structure */
 #   /* Ver:5 */
 # };


 # struct tagMQOR {
 #   MQCHAR48  ObjectName;      /* Object name */
 #   MQCHAR48  ObjectQMgrName;  /* Object queue manager name */
 # };


 # struct tagMQWIH {
 #   MQCHAR4   StrucId;         /* Structure identifier */
 #   MQLONG    Version;         /* Structure version number */
 #   MQLONG    StrucLength;     /* Length of MQWIH structure */
 #   MQLONG    Encoding;        /* Numeric encoding of data that */
 #                              /* follows MQWIH */
 #   MQLONG    CodedCharSetId;  /* Character-set identifier of data */
 #                              /* that follows MQWIH */
 #   MQCHAR8   Format;          /* Format name of data that follows */
 #                              /* MQWIH */
 #   MQLONG    Flags;           /* Flags */
 #   MQCHAR32  ServiceName;     /* Service name */
 #   MQCHAR8   ServiceStep;     /* Service step name */
 #   MQBYTE16  MsgToken;        /* Message token */
 #   MQCHAR32  Reserved;        /* Reserved */
 # };


 # struct tagMQXQH {
 #   MQCHAR4   StrucId;         /* Structure identifier */
 #   MQLONG    Version;         /* Structure version number */
 #   MQCHAR48  RemoteQName;     /* Name of destination queue */
 #   MQCHAR48  RemoteQMgrName;  /* Name of destination queue manager */
 #   MQMD1     MsgDesc;         /* Original message descriptor */
 # };


# Many others.


lstStructs = [  ]

ctypes_scanner.DoAll(lstStructs)