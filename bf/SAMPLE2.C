///////////////////////////////////////////////////////////////////////////////
//
// SAMPLE2.C - Example of Blowfish API call, using System linkage. 
//             Also demonstrates use of a random chaining seed, and the 
//             compression interface.
//
// Compile this, and link with ENCRYPT.LIB to use encryption functions in DLL
// (or link with ENCRYPT.OBJ to build stand-alone .EXE).
//
// Matthew Spencer, 23/5/96
// Updated 06/01/98, for version 1.62
//
///////////////////////////////////////////////////////////////////////////////
#include <stdio.h>    // for printf()
#include <string.h>   // for strlen()
#include <stdlib.h>   // for free()

#define BF_SYS_LINKAGE // to force "_System" linkage - NO EXTRA CHANGES REQUIRED
#include "encrypt.h"

int main(int argc, char * argv[])
{
   unsigned char text[] = "Example_Example_Example_Example_Example";
   unsigned char key[]  = "A sample key.";
   unsigned char seed[8];  
   unsigned char * comp_text, * decomp_text;
   unsigned long comp_len, decomp_len;

   // version 1.62: setup Chaining mode, and use a random IV (see blowfish.doc)
   SetChainingMode(ReInitialise);           
   SetChainingSeed(GetRandomBlock(&seed));  

   // intialise
   Initialise(key, strlen(key));   // call the _System linkage function

   // display original text
   printf("\nThe original text (%d bytes) is:  >>%s<<\n\n", strlen(text), text);

   // compress it.
   comp_len = Compress(text, strlen(text), &comp_text);
   comp_text[comp_len] = '\0';  // to help printf
   printf("After compression, the text is:   >>%s<<  (%ld bytes)\n\n", comp_text, comp_len);

   // call encryption
   EncryptBlock(comp_text, comp_len);          
   printf("After encryption, the text is:    >>%s<<\n\n", comp_text);

   // call decryption - should be the same as previous
   DecryptBlock(comp_text, comp_len);
   printf("After decryption, the text is:    >>%s<<\n\n", comp_text);

   // decompress it.
   decomp_len = Decompress(comp_text, comp_len, &decomp_text);
   decomp_text[decomp_len] = '\0';  // to help printf
   printf("After decompression, the text is: >>%s<<\n\n", decomp_text);

   // free the allocated memory
   #ifndef __DEBUG_ALLOC__
      free(comp_text);  
      free(decomp_text);
   #else
      _debug_free(comp_text, "sample2.c", 1);  
      _debug_free(decomp_text, "sample2.c", 2);
   #endif

   return 0;
}
