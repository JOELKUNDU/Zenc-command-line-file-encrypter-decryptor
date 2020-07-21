<h1>Zenc - command line file encrypter / decryptor</h1>
A command line cross platform File/Folder encryptor written in c++ and based on Crypto++ library 

<h2>How to use?</h2>        
       - Take the source file from the src file and paste it in an IDE.<br>
       - Make sure u set the c++ standard to stdc++17 and have cryptopp installed<Br>
       - compile and use the output. (refer bellow for exampple commands)<br>
       - If you change the output name from Zenc then replace Zenc from the commands given bellow with your output name.<br>

<h2>Encryption modes supported:</h2>
1.  AES-GCM with 2k tables<br>
2.  AES-GCM with 64k tables<br>
3.  AES-EAX<br>
4.  AES-CBC<br>
5.  AES-ECB<br>
6.  AES-CTR<br>       
7.  AES-CFB<br>
8.  AES-OFB<br>
(more methods will be added soon)<br>

<h2> How to use </h2>
Zenc [-h or -H/-e/-ed/-d/-dd] [FILE PATH] -m [mode] [-p/-np] [Password in case of using -p] [-t -g]<br>
-h or -H &nbsp; Help Menu<br>
-e &nbsp;&nbsp; Encrypt a file<br>
-ed&nbsp;&nbsp; Encrypt a directory<br>
-d &nbsp;&nbsp; Decrypt a file<br>
-dd&nbsp;&nbsp; Decrypt a directory<br>
-m &nbsp;&nbsp; Mode of Encryption / Decryption (gcm2k,gcm64k,eax,cbc,ecb,ctr,cfb,ofb)<br>
-p &nbsp;&nbsp; Password provided by the user (no limit in length or characters)<br>
-np&nbsp;&nbsp; Either a .zkey file is created or if -g is mentioned then a password is created<br>
-t &nbsp;&nbsp; Will encrypt/decrypt the titles and the extention<br>
-g &nbsp;&nbsp; Will generate a password of the length specified by the user<br> 
<br>

<h3>NOTE:</h3>
1. To delete files run it on an elevated terminal else Permission Denied error will occur. <br>
2. Time taken to do the operation will be displayed in microseconds in the end.

<h3>EXAMPLE COMMANDS:</h3>
1. To open the help book:<br>
       (on Windows)<br>

       Zenc -h
       Zenc -H
       Zenc

2. To Encrypt a file:<br>
       (on Windows)
      
       Zenc -e C:\test\test.txt -m gcm2k -p Password123 -t (encrypt with a passwprd)     
       Zenc -e C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)   
       Zenc -e C:\test\test.txt -m gcm2k -np -t (generate a keyfile)
       Zenc -e C:\test\test.txt -m gcm2k -np -t -g (generate a password)

3. To Encrypt a Directory :<br>
    (on Windows)<br>

       Zenc -ed C:\test\ -m gcm2k -p Password123 - t (encrypt with a passwprd)
       Zenc -ed C:\test\ -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)
       Zenc -ed C:\test\ -m gcm2k -np -t (generate a keyfile)
       Zenc -ed C:\test\ -m gcm2k -np -t -g (generate a password)

4. To Decrypt a file:<br>
    (on Windows)<br>

       Zenc -d C:\test\test.txt -m gcm2k -p Password123 -t (decrypt with a passwprd)
       Zenc -d C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)

5. To Decrypt a Directory :<br>
    (on Windows)<br>
    
       Zenc -dd C:\test\ -m gcm2k -p Password123 -t (decrypt with a passwprd)
       Zenc -dd C:\test\ -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)
       
NOTE: change Zenc according to your environment.       

