#ifndef XODBC_H
#define XODBC_H
#if defined(WIN32)
extern int xodbc_init (char * dsn);
extern int xodbc_execute(char *sql_str);
extern int xodbc_close();
#else
#define xodbc_init(x) (0)
#define xodbc_execute(x)    (0)
#define xodbc_close()       (0)
#endif
#endif
