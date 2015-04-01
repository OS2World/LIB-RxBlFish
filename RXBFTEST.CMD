/* Demo of how to use RXBFBISH.DLL */
/* NOTE: you MUST have the blowfish ENCRYPT.DLL availble
   (say,  in your LIBPATH).  This comes with the  blowfish .ZIP file  --
   search for blowfish on hobbes.nmsu.edu (or some other file repository)
*/

/* load the rxblfish functions */
   call RxFuncAdd 'rxBfGetVersion', 'RXBLFISH', 'rxBfGetVersion'
   arf=RxFuncAdd( 'rxBfSetVersion', 'RXBLFISH', 'rxBfSetVersion')
   call RxFuncAdd 'rxBfInitialise', 'RXBLFISH', 'rxBfInitialise'
   call RxFuncAdd 'rxBfEncrypt',    'RXBLFISH', 'rxBfEncrypt'
   call RxFuncAdd 'rxBfDecrypt',    'RXBLFISH', 'rxBfDecrypt'

call rxBfSetVersion(162)
say "RxBf version (as set in rxBfSetVersion): "||  rxBfGetVersion()

call rxBfInitialise('the key2')

rc = rxBfEncrypt("A 2nd test string to show that the Blowfish encryption really works.")
say "Encrypted: " rc

rc = rxBfDecrypt(rc)
say "rxBFDecrypt yields: " rc

rc = rxBfEncrypt('test.txt', 1)
say "rxBFEncrypt (of test.txt) status:" rc
rc = rxBfDecrypt('test.txt', 1)
say "rxBfDecrypt (of test.txt) status: " rc

rc = rxBfEncrypt('test.txt', 'test.enc')
say "Encrypt test.txt to test.enc, status=" rc
rc = rxBfDecrypt('test.enc', 'test.dec')
say "Decrypt test.enc, save results in test.dec. Status=" rc

exit
