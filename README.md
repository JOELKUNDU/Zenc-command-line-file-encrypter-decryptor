### Zenc ###
A command line cross platform File/Folder encryptor written in c++ and based on Crypto++ library 

How to use? <br>
Method 1: Take the .exe given in the release folder.
          Paste it somewhere on your PC.
          Press Shift and right-click there would be an option to open Powershell/cmd prompt
          Refer to the sample commands given bellow.
Method 2: Take the source file from the src file and paste it in an IDE.
          Make sure u set the c++ standard to stdc++17 and have cryptopp installed
          compile and use the exe just like before.

Encryption modes supported:
1.  AES-GCM with 2k tables
2.  AES-GCM with 64k tables
3.  AES-EAX
(more methods will be added soon)

::: Zenc HELPBOOK :::
Zenc <OPTIONS/TO ENCRYPT A FILE/TO ENCRYPT A FOLDER/TO DECRYPT A FILE/TO DECRYPT A FOLDER>

$$$$ OPTIONS $$$$

$ FOR HELP
- h or -H       OPEN HELPBOOK

$$$$ FOR ENCRYPTING $$$

$ TO ENCRYPT A FILE
-e <filepath> -m <mode> -p <password/key path> / -np -<additional_options>

-e              To encrypt a file.
<filepath>      Path to the file to be encrypted
-m              Choose the mode of encrytion

MODES SUPPORTED:
        1. gcm2k        GCM with 2K tables
        2. gcm64k       GCM with 64k tables
        3. eax          EAX mode

-p              If you want to enter the <password> or the <path> to an existing .key file
-np             If you don;t want to specify a password then a new .key file will be genrated in the same directoryADDITIONAL OPTIONS:
-t              Encrypts the name of the Files also


$ TO ENCRYPT A DIR
-ed <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>

-ed             To encrypt a dir.
<folderpath>    Path to the file to be encrypted
-m              Choose the mode of encrytion

MODES SUPPORTED:
        1. gcm2k        GCM with 2K tables
        2. gcm64k       GCM with 64k tables
        3. eax          EAX mode

-p              If you want to enter the <password> or the <path> to an existing .key file
-np             If you don;t want to specify a password then a new .key file will be genrated in the same directoryADDITIONAL OPTIONS:
-t              Encrypts the name of the Files also

$$$$ FOR DECRYPTING $$$$


$ TO DECRYPT A FILE
-d <filepath> -m <mode> -p <password/key path> / -np -<additional_options>

-d              To decrypt a file.
<filepath>      Path to the file to be decrypted
-m              Choose the mode of encrytion used

MODES SUPPORTED:
        1. gcm2k        GCM with 2K tables
        2. gcm64k       GCM with 64k tables
        3. eax          EAX mode

-p              Password used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption
ADDITIONAL OPTIONS:
-t              Mention this if the file names were encrypted


$ TO DECRYPT A FOLDER
-dd <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>

-dd             To decrypt a dir.
<folderpath>    Path to the file to be decrypted
-m              Choose the mode of encrytion used

MODES SUPPORTED:
        1. gcm2k        GCM with 2K tables
        2. gcm64k       GCM with 64k tables
        3. eax          EAX mode

-p              Password used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption
ADDITIONAL OPTIONS:
-t              Mention this if the file names were encrypted

EXAMPLE COMMANDS:
1. To open the help book:
    (on Windows)
    .\Zenc.exe -h
    .\Zenc.exe -H
    .\Zenc.exe
2. To Encrypt a file:
    (on Windows)
    .\Zenc.exe -e C:\test\test.txt -m gcm2k -p Password123 -t (encrypt with a passwprd)
    .\Zenc.exe -e C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)
    .\Zenc.exe -e C:\test\test.txt -m gcm2k -np -t (generate a keyfile)
3. To Encrypt a Directory :
    (on Windows)
    .\Zenc.exe -ed C:\test\ -m gcm2k -p Password123 - t (encrypt with a passwprd)
    .\Zenc.exe -ed C:\test\ -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)
    .\Zenc.exe -ed C:\test\ -m gcm2k -np -t (generate a keyfile)
4. To Decrypt a file:
    (on Windows)
    .\Zenc.exe -d C:\test\test.txt -m gcm2k -p Password123 -t (decrypt with a passwprd)
    .\Zenc.exe -d C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)
5. To Decrypt a Directory :
    (on Windows)
    .\Zenc.exe -dd C:\test\ -m gcm2k -p Password123 -t (decrypt with a passwprd)
    .\Zenc.exe -dd C:\test\ -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)
  
