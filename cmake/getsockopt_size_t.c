#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

int main() {(void)getsockopt (1, 1, 1, NULL, (size_t *)NULL);}
