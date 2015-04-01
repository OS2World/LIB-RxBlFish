/*  10 april 2003
Daniel Hellerstein, danielh@crosslink.net
Demonstrates a funny bug in RXBLFISH.
  To use, from an OS/2 command line, enter:
    x:>TEST
  a set of instructions will be listed.

  Note: you must have RXBLFISH.DLL and ENCRYPT.DLL in your libpath
*/


/* Load up advanced REXX functions */
foo=rxfuncquery('sysloadfuncs')
if foo=1 then do
  call RxFuncAdd 'SysLoadFuncs', 'RexxUtil', 'SysLoadFuncs'
  call SysLoadFuncs
end


call RxFuncAdd 'rxBfGetVersion', 'RXBLFISH', 'rxBfGetVersion' 
call RxFuncAdd 'rxBfSetVersion', 'RXBLFISH', 'rxBfSetVersion' 
call RxFuncAdd 'rxBfInitialise', 'RXBLFISH', 'rxBfInitialise' 
call RxFuncAdd 'rxBfEncrypt', 'RXBLFISH', 'rxBfEncrypt' 
call RxFuncAdd 'rxBfDecrypt', 'RXBLFISH', 'rxBfDecrypt'

parse arg todo
todo=translate(strip(todo))

string = "This is a sample string."

dodec=0
select
   when todo=1 then do
      akey='test1'
      ofile='t.1'
   end
   when todo=2 then do
      akey='test2'
      ofile='t.2'
   end
   when todo=11 then do
      akey='test1'
      ofile='t.11'
   end
   when todo='D11' then do
      akey='test1'
      ifile='t.11'
      dodec=1
   end
   when todo='D1' then do
      akey='test1'
      ifile='t.1'
      dodec=1
   end
   otherwise do
        say "This tests a bug in RXBLFISH "
        say "(you must have DECRYPT.DLL and RXBLFISH.DLL in your libpath)"
        say "To run this test, you need to run this program 5 times:"

        say "1) x:>TEST 1 "
        say  "    -- encrypts a string using 'test1', save to T.1 "

        say "2) x:>TEST 2 "
        say  "    -- encrypts a string using 'test2', save to T.2 "

        say "3) x:>TEST 11"
        say  "    -- encrypts a string using 'test1', save to T.11 "

        say "4) x:>TEST D11 "
        say  "    -- decrypts T.11, using 'test1' "

        say "5) x:>TEST D1 "
        say  "    -- decrypts T.1, using 'test1' "

        say "steps 4 and 5 should both work.. but only step 4 works "

        exit
  end
end 

if dodec=0 then do   /* encrypt the string */
  call RxFuncDrop 'rxBfInitialise' 
  call RxFuncAdd 'rxBfInitialise', 'RXBLFISH', 'rxBfInitialise' 
  say "Encrypting: " string
  call rxBfInitialise(akey)
  rc2 = rxBfencrypt(string)
  say "String, encrypted with ("akey")=" rc2
  foo=sysfiledelete(ofile)
  foo=charout(ofile,rc2,1)
  say "Encrypted string saved to "ofile
  foo=stream(ofile,'c','close')
end
else do     /* decrypte a string */
   call RxFuncDrop 'rxBfInitialise' 
   call RxFuncAdd 'rxBfInitialise', 'RXBLFISH', 'rxBfInitialise' 
   call rxBfInitialise(akey)
   ii=stream(ifile,'c','query size')
   stuff=charin(ifile,1,ii)
   foo=stream(ifile,'c','close')
   rc2 = rxBfdecrypt(stuff)
   say 'Decrypting 'ifile' with ('||akey||')'
   say " == "||rc2
end


exit
