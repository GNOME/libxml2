#ifndef XML_THREADS_H_PRIVATE__
#define XML_THREADS_H_PRIVATE__

void __xmlGlobalInitMutexLock(void);
void __xmlGlobalInitMutexUnlock(void);
void __xmlGlobalInitMutexDestroy(void);

void xmlInitThreadsInternal(void);
void xmlCleanupThreadsInternal(void);

#endif /* XML_THREADS_H_PRIVATE__ */
