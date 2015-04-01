/**************************************************/
/*                                                */
/* ENCRYPT.H - Public interface to ENCRYPT.DLL    */
/*                                                */
/* Author: Matthew Spencer (msspenc@ibm.net)      */
/*                                                */
/* Version: 1.62                                  */
/*                                                */
/* Date:    9th January, 1998                     */
/*                                                */
/**************************************************/
#ifndef ENCRYPT_H
#define ENCRYPT_H

/*
** Chaining mode enumeration - see blowfish.doc for explanation
*/
enum ChainingMode{ReInitialise, CarryForward};

/*
** Prototypes.  There are 2 sets of functions.  Use the ones which
** your compiler supports.  IBM C-Set and VisualAge C++ use _Optlink
** as the default linkage, while Borland C++ only supports _System.
**
** New with Version 1.62:  I have used a couple of macros to save having
** to declare both sets of functions.  Borland C++ users (or those wishing
** to call the _System linkage functions) should revert to calling "Initialise"
** instead of "BfInitialise", and so on.
** Thanks to Jeremy Mathers for this idea.
**
*/

#ifdef __BORLANDC__
   #define BF_SYS_LINKAGE
#endif

#ifndef BF_SYS_LINKAGE
   #define BF_LINKAGE(func) _Optlink func
#else
   #define FUNC_NAME(func) Bf##func
   #define SetBfVersion    FUNC_NAME(SetVersion     )
   #define GetBfVersion    FUNC_NAME(GetVersion     )
   #define SetChainingMode FUNC_NAME(SetChainingMode)
   #define SetChainingSeed FUNC_NAME(SetChainingSeed)
   #define Initialise      FUNC_NAME(Initialise     )
   #define EncryptBlock    FUNC_NAME(EncryptBlock   )
   #define DecryptBlock    FUNC_NAME(DecryptBlock   )
   #define GetRandomBlock  FUNC_NAME(GetRandomBlock )
   #define BF_LINKAGE(func) _System func
#endif

void BF_LINKAGE(SetBfVersion   )(long version);           /* use version = 162, for compatibility */
long BF_LINKAGE(GetBfVersion   )(void);                   /* query version being used             */
void BF_LINKAGE(SetChainingMode)(int mode);               /* see blowfish.doc                     */
void BF_LINKAGE(SetChainingSeed)(unsigned char * buffer); /* buffer size == 8, exactly!           */
void BF_LINKAGE(Initialise     )(unsigned char * key,    short length);          /* length <= 56  */
void BF_LINKAGE(EncryptBlock   )(unsigned char * buffer, unsigned long length);  /* length >= 8   */
void BF_LINKAGE(DecryptBlock   )(unsigned char * buffer, unsigned long length);  /* length >= 8   */
unsigned char *
     BF_LINKAGE(GetRandomBlock )(unsigned char * buffer); /* buffer size == 8, exactly!           */

/*********************************************************************************/
/*                                                                               */
/* Compression/Decompression functions: (new with 1.62)                          */
/*                                                                               */
/* Both the Compress() and Decompress() functions take 3 arguments.  The first   */
/* is a pointer (unsigned char *) to the original data.  The second is the       */
/* length of the original data (unsigned long), and the third is a pointer to    */
/* a pointer (unsigned char **), which is set by the functions, and which will   */
/* point to the compressed (or decompressed) data after the operation.  Both     */
/* functions return the length (unsigned long) of the compressed (or             */
/* decompressed) data.                                                           */
/*                                                                               */
/* NOTE that these functions both allocate memory, and that it is the            */
/* responsiblity of the calling modules to free this memory.  The original data  */
/* is not altered in any way by these functions.                                 */
/*                                                                               */
/*********************************************************************************/

#ifdef BF_SYS_LINKAGE
   #define Compress        FUNC_NAME(Compress       )
   #define Decompress      FUNC_NAME(Decompress     )
#endif

unsigned long BF_LINKAGE(Compress  )(unsigned char *  inputData,
                                     unsigned long    inputLength,
                                     unsigned char ** outputData);

unsigned long BF_LINKAGE(Decompress)(unsigned char *  inputData,
                                     unsigned long    inputLength,
                                     unsigned char ** outputData);
/*
** Possible return codes
*/
#ifndef NO_ERROR
  #define NO_ERROR                                   0
#endif
#define BYTE_COUNT_DIFFERS_FROM_EXPECTED_LENGTH      1
#define ERROR_DELETING_SOURCE_FILE                   3
#define ERROR_OPENING_SOURCE_FILE                    7
#define ERROR_OPENING_TARGET_FILE                    8
#define ERROR_READING_SOURCE_FILE                    9
#define INCORRECT_KEY                               11
#define INCORRECT_SIGNATURE_IN_SOURCE_FILE          12
#define OPERATION_ABORTED                           13
#define INSUFFICIENT_SPACE_ON_TARGET_DRIVE          16
#define KEY_HAS_ZERO_LENGTH                         18
#define NO_FILES_MATCH_FILESPEC                     19
#define FILE_HAS_ZERO_LENGTH                        20
#define SINGLE_TARGET_MULTI_SOURCE                  21
#define FILENAME_PROCESSING_ERROR                   22
#define ERROR_DURING_TEMPORARY_FILE_RENAME          23
#define TARGET_NAME_MATCHES_PREVIOUS_TARGET         24
#define KEYS_DO_NOT_MATCH                           25
#define SKIPPED_ALREADY_ENCRYPTED                   26
#define SKIPPED_ALREADY_DECRYPTED                   27
#define WILDCARDS_NOT_ALLOWED_IN_TARGET             28
#define OLD_BLOWFISH_VERSION                        29

#define SYNTAX_ERROR                                98
#define UNKNOWN_ERROR                               99

#endif
