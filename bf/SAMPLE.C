///////////////////////////////////////////////////////////////////////////////
//
// SAMPLE.C - Example of Blowfish API call.
//
// Compile this, and link with ENCRYPT.LIB to use encryption functions in DLL
// (or link with ENCRYPT.OBJ to build stand-alone .EXE).
//
// Matthew Spencer, 18/8/95
// Updated 06/01/98, for version 1.62
//
///////////////////////////////////////////////////////////////////////////////
#include <stdio.h>    // for printf()
#include <string.h>   // for strlen()
#include "encrypt.h"

int main(int argc, char * argv[])
{
   unsigned char text[] = "This is the sample text to encrypt";   
   unsigned char key[]  = "A sample key.";
   int len = strlen(text);

   // version 1.62: setup Chaining mode
   SetChainingMode(ReInitialise);        

   // intialise
   Initialise(key, strlen(key));

   // display original text
   printf("\nThe original text (%d bytes) is: >>%s<<\n\n", len, text);

   // call encryption
   EncryptBlock(text, len);          
   printf("After encryption, the text is:   >>%s<<\n\n", text);

   // call decryption - should be the same as the original
   DecryptBlock(text, len);
   printf("After decryption, the text is:   >>%s<<\n\n", text);

   return 0;
}
