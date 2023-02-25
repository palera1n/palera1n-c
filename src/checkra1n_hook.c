#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

int my_vasprintf(char **ret, const char *format, va_list ap) {
    if (strstr(format, "Download mode device found") != NULL) {
        _exit(0);
    }
    return vasprintf(ret, format, ap);
}

DYLD_INTERPOSE(my_vasprintf, vasprintf)
