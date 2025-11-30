ERROR{exit(0);}

struct ustr{uint16_t buffer[256];};

syscall::NtOpenFile:entry
{
   this->deleted = arg5 & 0x00001000; /* & with FILE_DELETE_ON_CLOSE */

  if (this->deleted) {
        this->attr = (nt`_OBJECT_ATTRIBUTES*)
            copyin(arg2, sizeof(nt`_OBJECT_ATTRIBUTES));

        if (this->attr->ObjectName) {
            this->objectName = (nt`_UNICODE_STRING*)
                copyin((uintptr_t)this->attr->ObjectName,
                       sizeof(nt`_UNICODE_STRING));
          
            this->fname = (uint16_t*)
                copyin((uintptr_t)this->objectName->Buffer,
                       this->objectName->Length);

            printf("Process %s PID %d deleted file %*ws \n", execname,pid, 
			this->objectName->Length / 2, 
			 ((struct ustr*)this->fname)->buffer);
        }
    }
}