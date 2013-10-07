#ifndef __POPEN_RWE
#define __POPEN_RWE

int popenRWE(int *rwepipe, const char *path);
int pcloseRWE(int pid, int *rwepipe);

#endif
