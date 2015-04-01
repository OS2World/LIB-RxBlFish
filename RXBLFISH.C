
/***********************************************************************/
/*                                                                     */
/*   RxBlfish - Copyright (C) 2000 Michal Necasek <mike@mendelu.cz>    */
/*           Specification - Daniel Hellerstein <danielh@econ.ag.gov>  */
/*                                                                     */
/*   This code is in the public domain                                 */
/*                                                                     */
/*   This code is based on Matthew Spencer's ENCRYPT library           */
/*                                                                     */
/***********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define  INCL_REXXSAA
#include <os2.h>
#include <rexxsaa.h>

#include "encrypt.h"

/* exported functions */
RexxFunctionHandler RxBfGetVersion;
RexxFunctionHandler RxBfSetVersion;
RexxFunctionHandler RxBfInitialise;
RexxFunctionHandler RxBfEncrypt;
RexxFunctionHandler RxBfDecrypt;
RexxFunctionHandler RxBfFileEncrypt;
RexxFunctionHandler RxBfFileDecrypt;


#define  INVALID_ROUTINE 40            /* Raise Rexx error           */
#define  VALID_ROUTINE    0            /* Successful completion      */

/* error codes */
#define  NO_UTIL_ERROR    "0"          /* No error whatsoever        */
#define  ERROR_NOMEM      "2"          /* Insufficient memory        */
#define  ERROR_FILEOPEN   "3"          /* Error opening file         */
#define  ERROR_ENGINE     "4"          /* Blowfish error             */
#define  ERROR_REXXVAR    "5"          /* Rexx variable pool error   */

#define  MAX             256
#define  IBUF_LEN      32768           /* buffer length              */
#define  BUFLEN        32768           /* buffer length              */
#define  MAX_NAME_LEN    256           /* file name length           */

/*********************************************************************/
/* RxStemData                                                        */
/*   Structure which describes a generic                             */
/*   stem variable.                                                  */
/*********************************************************************/

typedef struct RxStemData {
    SHVBLOCK shvb;                     /* Request block for RxVar    */
    CHAR ibuf[IBUF_LEN];               /* Input buffer               */
    CHAR varname[MAX];                 /* Buffer for the variable    */
                                       /* name                       */
    CHAR stemname[MAX];                /* Buffer for the variable    */
                                       /* name                       */
    ULONG stemlen;                     /* Length of stem.            */
    ULONG vlen;                        /* Length of variable value   */
    ULONG j;                           /* Temp counter               */
    ULONG tlong;                       /* Temp counter               */
    ULONG count;                       /* Number of elements         */
                                       /* processed                  */
} RXSTEMDATA;

#define BUILDRXSTRING(t, s) { \
  strcpy((t)->strptr,(s));\
  (t)->strlength = strlen((s)); \
}


/* RxBfGetVersion - return version of the Blowfish library                 */
/* Note: by default this function returns zero - bug in the bfish DLL?     */
ULONG RxBfGetVersion(PSZ name, ULONG numargs, RXSTRING args[],
                     PSZ queuename, RXSTRING *retstr) {
   char s[64];

   BUILDRXSTRING(retstr, itoa(GetBfVersion(), s, 10)); /* pass back result  */
   return VALID_ROUTINE;
}

/* RxBfSetVersion - set version of the Blowfish library for compatibility  */
ULONG RxBfSetVersion(PSZ name, ULONG numargs, RXSTRING args[],
                     PSZ queuename, RXSTRING *retstr) {

   SetBfVersion(atoi(args[0].strptr));

   BUILDRXSTRING(retstr, NO_UTIL_ERROR);
   return VALID_ROUTINE;
}

/* RxBfInitialise - set Blowfish encryption key                            */
ULONG RxBfInitialise(PSZ name, ULONG numargs, RXSTRING args[],
                     PSZ queuename, RXSTRING *retstr) {

   BUILDRXSTRING(retstr, NO_UTIL_ERROR);
   /* check  arguments */
   if (numargs !=  1 ||
       !RXVALIDSTRING(args[0]))
      return INVALID_ROUTINE;                /* raise an error             */

   Initialise(args[0].strptr, args[0].strlength);
   SetChainingMode(ReInitialise);

   return VALID_ROUTINE;
}

/* RxBfDecrypt(instring) - return Blowfish decrypted input string          */
ULONG RxBfDecrypt(PSZ name, ULONG numargs, RXSTRING args[],
                  PSZ queuename, RXSTRING *retstr) {
   int   err;
   CHAR  *decrypt = NULL;
   ULONG len;

   BUILDRXSTRING(retstr, NO_UTIL_ERROR); /* pass back result               */

   /* check  arguments */
   if (numargs ==  1 && RXVALIDSTRING(args[0])) {
      /* encrypt a RxString */
      len = args[0].strlength;

      /* allocate memory for the encrypted string - we can't just use the
         original storage */
      err = DosAllocMem((PVOID*)&decrypt, len + 64, PAG_READ | PAG_WRITE | OBJ_TILE | PAG_COMMIT);
      if (err)
         return INVALID_ROUTINE;

      memcpy(decrypt, args[0].strptr, len);
      DecryptBlock(decrypt, len);

      retstr->strptr    = decrypt;
      retstr->strlength = len;

      return VALID_ROUTINE;
   }
   else if (numargs ==  2 && RXVALIDSTRING(args[0])) {
      /* decrypt a file */
      FILE *f, *g;
      int  count, pos = 0;
      BOOL fRewrite = FALSE;

      fRewrite = !strcmp(args[1].strptr, "1");

      if (fRewrite) {
         if ((f = fopen(args[0].strptr, "rb+")) == NULL) {
            BUILDRXSTRING(retstr, ERROR_FILEOPEN);
            return VALID_ROUTINE;
         }
      }
      else {
         if ((f = fopen(args[0].strptr, "rb")) == NULL) {
            BUILDRXSTRING(retstr, ERROR_FILEOPEN);
            return VALID_ROUTINE;
         }
         if ((g = fopen(args[1].strptr, "wb")) == NULL) {
            BUILDRXSTRING(retstr, ERROR_FILEOPEN);
            return VALID_ROUTINE;
         }
      }

      err = DosAllocMem((PVOID*)&decrypt, BUFLEN, PAG_READ | PAG_WRITE | OBJ_TILE | PAG_COMMIT);
      if (err) {
         fclose(f);
         if (!fRewrite)
            fclose(g);

         BUILDRXSTRING(retstr, ERROR_NOMEM);
         return VALID_ROUTINE;
      }

      while ((count = fread(decrypt, 1, BUFLEN, f)) == BUFLEN) {
         DecryptBlock(decrypt, BUFLEN);
         if (fRewrite) {
            fseek(f, pos, SEEK_SET);
            fwrite(decrypt, 1, count, f);
            pos += count;
            fseek(f, pos, SEEK_SET);
         }
         else {
            fwrite(decrypt, 1, count, g);
         }
      }
      DecryptBlock(decrypt, count);
      if (fRewrite) {
         fseek(f, pos, SEEK_SET);
         fwrite(decrypt, 1, count, f);
      }
      else {
         fwrite(decrypt, 1, count, g);
      }

      fclose(f);
      if (!fRewrite)
         fclose(g);
      DosFreeMem(decrypt);
      return VALID_ROUTINE;
   }

   return INVALID_ROUTINE;
}

/* RxBfEncrypt(instring) - return Blowfish encrypted input string;         */
/* alternately encrypt file contents (if parameter 2 exists)               */
ULONG RxBfEncrypt(PSZ name, ULONG numargs, RXSTRING args[],
                  PSZ queuename, RXSTRING *retstr) {
   int   err;
   CHAR  *crypt = NULL;
   ULONG len;

   BUILDRXSTRING(retstr, NO_UTIL_ERROR); /* pass back result               */

   /* check  arguments */
   if (numargs ==  1 && RXVALIDSTRING(args[0])) {
      /* encrypt a RxString */
      len = args[0].strlength;

      /* allocate memory for the encrypted string - we can't just use the
         original storage */
      err = DosAllocMem((PVOID*)&crypt, len + 64, PAG_READ | PAG_WRITE | OBJ_TILE | PAG_COMMIT);
      if (err)
         return INVALID_ROUTINE;

      memcpy(crypt, args[0].strptr, len);
      EncryptBlock(crypt, len);

      retstr->strptr    = crypt;
      retstr->strlength = len;

      return VALID_ROUTINE;
   }
   else if (numargs ==  2 && RXVALIDSTRING(args[0]) && RXVALIDSTRING(args[1])) {
      /* encrypt a file */
      FILE *f, *g;
      int  count, pos = 0;
      BOOL fRewrite = FALSE;

      fRewrite = !strcmp(args[1].strptr, "1");

      if (fRewrite) {
         if ((f = fopen(args[0].strptr, "rb+")) == NULL) {
            BUILDRXSTRING(retstr, ERROR_FILEOPEN);
            return VALID_ROUTINE;
         }
      }
      else {
         if ((f = fopen(args[0].strptr, "rb")) == NULL) {
            BUILDRXSTRING(retstr, ERROR_FILEOPEN);
            return VALID_ROUTINE;
         }
         if ((g = fopen(args[1].strptr, "wb")) == NULL) {
            BUILDRXSTRING(retstr, ERROR_FILEOPEN);
            return VALID_ROUTINE;
         }
      }

      err = DosAllocMem((PVOID*)&crypt, BUFLEN, PAG_READ | PAG_WRITE | OBJ_TILE | PAG_COMMIT);
      if (err) {
         fclose(f);
         if (!fRewrite)
            fclose(g);
         BUILDRXSTRING(retstr, ERROR_NOMEM);
         return VALID_ROUTINE;
      }

      while ((count = fread(crypt, 1, BUFLEN, f)) == BUFLEN) {
         EncryptBlock(crypt, count);
         if (fRewrite) {
            fseek(f, pos, SEEK_SET);
            fwrite(crypt, 1, count, f);
            pos += count;
            fseek(f, pos, SEEK_SET);
         }
         else {
            fwrite(crypt, 1, count, g);
         }
      }
      EncryptBlock(crypt, count);
      if (fRewrite) {
         fseek(f, pos, SEEK_SET);
         fwrite(crypt, 1, count, f);
      }
      else {
         fwrite(crypt, 1, count, g);
      }

      fclose(f);
      if (!fRewrite)
         fclose(g);
      DosFreeMem(crypt);

      return VALID_ROUTINE;
   }
   return INVALID_ROUTINE;            /* raise an error                 */
}
