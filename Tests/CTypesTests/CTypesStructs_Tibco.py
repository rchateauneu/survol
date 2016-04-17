import ctypes
import ctypes_scanner
from ctypes_scanner import POINTER_T

# C est le hader qui nous interesse, qui contient source et destination.
# On ne s interesse pas au contenu.

# tibrvlisten -network "190.231.54.20" -service "5420" -daemon "tcp:7500"
# C:\>tibrvlisten -service "5420" -network ";190.231.54.20" -daemon "tcp:remotehost:7500"  TEST.REPLY

# Un netwrok sniffer peut nous donner ls atrcture des messages.
# Reste a les scanner dans la memoire du process,
# si les messages sont suffisamment faciles a identifier.

# http://seclists.org/nmap-dev/2014/q2/522

# Tib

# typedef enum
# {
# TIBRV_OK                        = 0,
# TIBRV_IPM_ONLY                  = 117
# } tibrv_status;


# class TibrvStatus
# {
# tibrv_status _status;
# };

# class TibrvDispatchable
# {
# };

# typedef tibrv_u32               tibrvId;

# typedef tibrvId                 tibrvEvent;
# typedef tibrvEvent              tibrvPollEvent;
# typedef tibrvId                 tibrvQueue;
# typedef tibrvQueue              tibrvPollQueue;
# typedef tibrvId                 tibrvTransport;
# typedef tibrvId                 tibrvQueueGroup;
# typedef tibrvId                 tibrvDispatchable;
# typedef tibrvId                 tibrvDispatcher;

# class TibrvQueue : public TibrvDispatchable
# {
# tibrvQueue _queue;
# TibrvQueueOnComplete* _completeCallback;
# void* _closure;
# };

# class TibrvQueueOnComplete
# {
# }

# class TibrvQueueGroup : public TibrvDispatchable
# {
# tibrvQueueGroup  _queueGroup;
# };

# class TibrvDispatcher
# {
# tibrvDispatcher    _dispatcher;
# TibrvDispatchable* _dispatchable;
# };


# class TibrvTransport
# {
# tibrvTransport  _transport;
# };

# class TibrvProcessTransport : public TibrvTransport
# {
# };

# class TibrvNetTransport : public TibrvTransport
# {
# };

# class TibrvVcTransport : public TibrvTransport
# {
# };

# class TibrvEvent
# {
# tibrvEvent      _event;
# TibrvCallback*  _callback;
# TibrvVectorCallback* _vectorCallback;
# TibrvEventOnComplete* _completeCallback;
# void *          _closure;
# TibrvQueue*     _queue;
# tibrvEventType  _objType;
# };


# class TibrvListener : public TibrvEvent
# {
# TibrvTransport* _transport;
# };

# class TibrvVectorListener : public TibrvEvent
# {
# TibrvTransport* _transport;
# };

# class TibrvTimer : public TibrvEvent
# {
# };

# class TibrvEventOnComplete
# {
# };

# class TibrvCallback
# {
# };

# # Mais est ce que la VTBL est prise en compte ???

# class TibrvMsgCallback : public TibrvCallback
# {
# };

# class TibrvTimerCallback : public TibrvCallback
# {
# };

# class TibrvIOCallback : public TibrvCallback
# {
# };

# typedef struct tibrvMsgField
# {
# const char*                 name;
# tibrv_u32                   size;
# tibrv_u32                   count;
# tibrvLocalData              data;
# tibrv_u16                   id;
# tibrv_u8                    type;
# } tibrvMsgField;


# class TibrvMsgField : public tibrvMsgField
# {
# };

# typedef struct tibrvMsgDateTime
# {
# tibrv_i64                   sec;
# tibrv_u32                   nsec;
# } tibrvMsgDateTime;

# class TibrvMsgDateTime : public tibrvMsgDateTime
# {

# };

# typedef struct __tibrvMsg*      tibrvMsg;

# class TibrvMsg
# {
# tibrvMsg     _msg;
# tibrv_bool   _detached;
# tibrv_status _status;
# tibrv_u32    _initsize;
# TibrvEvent*  _event;

# };


#####  VOIR AUSSI LE CONTENU DEtibrv/types.h !!!!

lstStructs = [  ]
ctypes_scanner.DoAll(lstStructs)