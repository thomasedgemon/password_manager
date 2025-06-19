Stateless password manager
features:
1. master password can be forcibly removed from session memory.
2. passwords are decrypted one at a time.
3. app has banner displaying bool - is master password currently in session memory?
4. decryptions have limited lifespans in session. 
5. 





as of 6/13/25:

app currently:
1. hardcodes location of config file, and is OS-agnostic
2. forces user to define a filepath for encrypted file if it doesnt already exist.
3. if user does not define a filepath, script closes.

next things to do:
1. select symmetric encryption algo. probably just the most robust available, and not made from scratch.
2. build out reading from and writing to ciphertext csv. do not encrypt common names, only passwords. 
3. determine how to reference a common name. probably as a drop-down to select from.
4. functionality to add a password.
5. functionality to rm a password.
6. functionality to generate a new password for the user, where they
   can choose length. will force alphanumeric with special characters.
   probably use os.urandom for maximal entropy/domain space  
7. ability to import from flashdrive for porting to another machine
   
