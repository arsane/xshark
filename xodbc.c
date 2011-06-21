#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <sql.h>
#include <sqlext.h>
#include "xodbc.h"
#include "xutils.h"

#define MAXDSN       (25)
#define MAXUID       (25)
#define MAXAUTHSTR   (25)
#define MAXBUFLEN    (255)
#define SIZEOFTEXT   (300000)

HENV henv = SQL_NULL_HENV;
HDBC hdbc1 = SQL_NULL_HDBC;
HSTMT hstmt1 = SQL_NULL_HSTMT;
char logstring[MAXBUFLEN] = "";

extern int opt_disable_odbc_error;

static void
process_log_messages(HENV plm_henv, HDBC plm_hdbc,
                        HSTMT plm_hstmt, char *logstring)
{
   RETCODE plm_retcode = SQL_SUCCESS;
   UCHAR plm_szSqlState[MAXBUFLEN] = "";
   UCHAR plm_szErrorMsg[MAXBUFLEN] = "";
   SDWORD plm_pfNativeError = 0L;
   SWORD plm_pcbErrorMsg = 0;

   ERR("%s\n", logstring);
   while (plm_retcode != SQL_NO_DATA_FOUND) {
      plm_retcode = SQLError(plm_henv, plm_hdbc,
                plm_hstmt, plm_szSqlState,
               &plm_pfNativeError,
                plm_szErrorMsg, MAXBUFLEN - 1,
               &plm_pcbErrorMsg);
      if (plm_retcode != SQL_NO_DATA_FOUND){
         ERR("szSqlState = %s\n", plm_szSqlState);
         ERR("pfNativeError = %d\n", plm_pfNativeError);
         ERR("szErrorMsg = %s\n", plm_szErrorMsg);
         ERR("pcbErrorMsg = %d\n\n", plm_pcbErrorMsg);
      }
   }
}

int xodbc_init(char *dsn)
{
   RETCODE retcode;
   UCHAR szUID[MAXUID+1] = "";
   UCHAR szAuthStr[MAXAUTHSTR+1] = "";

   /* allocate the ODBC environment and save handle. */
   retcode = SQLAllocEnv (&henv);

   /* allocate ODBC connection and connect. */
   retcode = SQLAllocConnect(henv, &hdbc1);
   retcode = SQLConnect(hdbc1, dsn, (SWORD)strlen(dsn),
               szUID, (SWORD)strlen(szUID),szAuthStr,
               (SWORD)strlen(szAuthStr));
   if ( (retcode != SQL_SUCCESS) &&
        (retcode != SQL_SUCCESS_WITH_INFO) ) {
         process_log_messages(henv,
                 hdbc1,
                 hstmt1,
                 "SQLConnect() Failed\n\n");
         return(-1);
   } else {
      INFO("ODBC %s connect successful!\n", dsn);
   }

   /* allocate a statement handle. */
   retcode = SQLAllocStmt(hdbc1,&hstmt1);

   return 0;
}

int xodbc_execute(char *sql_str)
{
   RETCODE retcode;

   retcode = SQLExecDirect(hstmt1, sql_str, SQL_NTS);

   if ( (retcode != SQL_SUCCESS) &&
        (retcode != SQL_SUCCESS_WITH_INFO) &&
        (retcode != SQL_NEED_DATA) ) {
       //TODO: deal with different return code.
       if (opt_disable_odbc_error)
           return -1;
       process_log_messages(henv, hdbc1, hstmt1,
               "SQLExecute Failed\n\n");
       return(-1);
   }

   return 0;
}

int xodbc_close()
{
   /* Clean up. */
   SQLCancel(hstmt1);
   SQLFreeStmt(hstmt1, SQL_DROP);
   SQLDisconnect(hdbc1);
   SQLFreeConnect(hdbc1);
   SQLFreeEnv(henv);

   return 0;
}
