<h1>Zenc - command line file encrypter / decryptor</h1>
A command line cross platform File/Folder encryptor written in c++ and based on Crypto++ library 

<h2>How to use?</h2> <br>
<h3>Method 1:</h3> <br>
       - Take the .exe given in the release folder.<br>
       - Paste it somewhere on your PC.<br>
       - Press Shift and right-click there would be an option to open Powershell/cmd prompt<br>
       - Refer to the sample commands given bellow.<br>
<h3>Method 2:</h3> <br>
       - Take the source file from the src file and paste it in an IDE.<br>
       - Make sure u set the c++ standard to stdc++17 and have cryptopp installed
       - compile and use the exe just like before.<br>

<h2>Encryption modes supported:</h2>
1.  AES-GCM with 2k tables<br>
2.  AES-GCM with 64k tables<br>
3.  AES-EAX<br>
(more methods will be added soon)<br>

<h2>::: Zenc HELPBOOK :::<br></h2>
Zenc [OPTIONS/TO ENCRYPT A FILE/TO ENCRYPT A FOLDER/TO DECRYPT A FILE/TO DECRYPT A FOLDER]<br>
<br>
<h3>$$$$ OPTIONS $$$$</h3><br>
<br>
$ FOR HELP<br>
- h or -H       OPEN HELPBOOK<br>
<br>
<h3>$$$$ FOR ENCRYPTING $$$</h3><br>
<br>
$ TO ENCRYPT A FILE<br>
-e [filepath] -m [mode] -p [password/key path] / -np -[additional_options]<br>
<br>
-e              To encrypt a file.<br>
<filepath>      Path to the file to be encrypted<br>
-m              Choose the mode of encrytion<br>
<br>
MODES SUPPORTED:<br>
        1. gcm2k        GCM with 2K tables<br>
        2. gcm64k       GCM with 64k tables<br>
        3. eax          EAX mode<br>
<br>
-p              If you want to enter the <password> or the <path> to an existing .key file<br>
-np             If you don;t want to specify a password then a new .key file will be genrated in the same directoryADDITIONAL OPTIONS:<br>
-t              Encrypts the name of the Files also<br>
<br>
<br>
$ TO ENCRYPT A DIR<br>
-ed [folderpath] -m [mode] -p [password/key path] / -np -[additional_options]<br>
<br>
-ed             To encrypt a dir.<br>
<folderpath>    Path to the file to be encrypted<br>
-m              Choose the mode of encrytion<br>
<br>
MODES SUPPORTED:<br>
        1. gcm2k        GCM with 2K tables<br>
        2. gcm64k       GCM with 64k tables<br>
        3. eax          EAX mode<br>
<br>
-p              If you want to enter the <password> or the <path> to an existing .key file<br>
-np             If you don;t want to specify a password then a new .key file will be genrated in the same directoryADDITIONAL OPTIONS:<br>
-t              Encrypts the name of the Files also<br>
<br>
<h3>$$$$ FOR DECRYPTING $$$$</h3><br>
<br>
<br>
$ TO DECRYPT A FILE<br>
-d [filepath] -m [mode] -p [password/key path] / -np -[additional_options]<br>
<br>
-d              To decrypt a file.<br>
<filepath>      Path to the file to be decrypted<br>
-m              Choose the mode of encrytion used
<br>
MODES SUPPORTED:<br>
        1. gcm2k        GCM with 2K tables<br>
        2. gcm64k       GCM with 64k tables<br>
        3. eax          EAX mode<br>
<br>
-p              Password used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption<br>
ADDITIONAL OPTIONS:<br>
-t              Mention this if the file names were encrypted<br>
<br>
<br>
$ TO DECRYPT A FOLDER<br>
-dd [folderpath] -m [mode] -p [password/key path] / -np -[additional_options]<br>
<br>
-dd             To decrypt a dir.<br>
<folderpath>    Path to the file to be decrypted<br>
-m              Choose the mode of encrytion used<br>
<br>
MODES SUPPORTED:<br>
        1. gcm2k        GCM with 2K tables<br>
        2. gcm64k       GCM with 64k tables<br>
        3. eax          EAX mode<br>

-p              Password used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption<br>
ADDITIONAL OPTIONS:<br>
-t              Mention this if the file names were encrypted<br>
<br>

<h3>EXAMPLE COMMANDS:<br></h3>
1. To open the help book:<br>
       (on Windows)<br>

       .\Zenc.exe -h
       .\Zenc.exe -H
       .\Zenc.exe

2. To Encrypt a file:<br>
       (on Windows)
      
       .\Zenc.exe -e C:\test\test.txt -m gcm2k -p Password123 -t (encrypt with a passwprd)     
       .\Zenc.exe -e C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)   
       .\Zenc.exe -e C:\test\test.txt -m gcm2k -np -t (generate a keyfile)

3. To Encrypt a Directory :<br>
    (on Windows)<br>

       .\Zenc.exe -ed C:\test\ -m gcm2k -p Password123 - t (encrypt with a passwprd)
       .\Zenc.exe -ed C:\test\ -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)
       .\Zenc.exe -ed C:\test\ -m gcm2k -np -t (generate a keyfile)

4. To Decrypt a file:<br>
    (on Windows)<br>

       .\Zenc.exe -d C:\test\test.txt -m gcm2k -p Password123 -t (decrypt with a passwprd)
       .\Zenc.exe -d C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)

5. To Decrypt a Directory :<br>
    (on Windows)<br>
    
       .\Zenc.exe -dd C:\test\ -m gcm2k -p Password123 -t (decrypt with a passwprd)
       .\Zenc.exe -dd C:\test\ -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)

