#ifndef XUTILS_H
#define XUTILS_H
#include <stdio.h>

extern unsigned int opt_verbosity;

#if defined(WIN32)
#define unlikely(x)    x
#else
#define unlikely(x)  __builtin_expect(!!(x), 0)
#endif  /* defined(WIN32) */


#define ERR(fmt, ...)                                       \
    fprintf(stderr, "Error: " fmt,  ##__VA_ARGS__)

#define WARN(fmt, ...)                                      \
    do {                                                    \
        if (opt_verbosity > 0)                              \
            fprintf(stderr, "Warning: " fmt, ##__VA_ARGS__);\
    }while(0);

#define INFO(fmt, ...)                                      \
    do {                                                    \
        if (opt_verbosity > 1)                              \
            fprintf(stderr, "Info: " fmt, ##__VA_ARGS__);   \
    }while(0);

#define DBG(fmt, ...)                                       \
    do {                                                    \
        if (opt_verbosity > 2)                              \
            fprintf(stderr, "Debug: " fmt, ##__VA_ARGS__);  \
    }while(0);

#define BUG_ON(condition)                                   \
    do {                                                    \
        if (unlikely(condition))                            \
            ERR("condition not respected on line %s:%d\n",  \
                    __FILE__, __LINE__);           \
    } while(0)

#define WARN_ON(condition)                                  \
    do {                                                    \
        if (unlikely(condition))                            \
            WARN("condition not respected on line %s:%d\n", \
                    __FILE__, __LINE__);                    \
    } while(0)

#endif
