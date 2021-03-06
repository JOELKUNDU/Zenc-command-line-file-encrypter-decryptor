<h1>Zenc - command line file encrypter / decryptor</h1>
       
A command line cross platform File/Folder encryptor written in c++ and based on Crypto++ library <br>
<a href = "https://joelkundu.github.io/Zenc/"> Visit the site </a><br>

Checkout CONTRIBUTING.md to see the contributing guidelines.

<h2>How to use?</h2>  
<h3>Windows</h3>
-have g++ and libcrypto++(crypto++) preinstalled and configured<br>
-Run Make.bat<br>
else (if you are having issues with g++ and libcrypto++)<br>
-run make_path.bat, this will create a directory c:\Zenc <br>
-Copy exe from release folder to c:\Zenc and use it.<br>

<h3>Linux</h3>
Clone the repository and open a terminal in the root and use:

       sudo apt-get install g++
       sudo apt-get install libcryptopp++
       g++ src/Zenc.cpp -std=c++17 -lstdc++fs -lcrypto++ -o /usr/bin/Zenc
 
NOTE: optional - upx the executable (-9 --lzma) (slight boost in performance) 
<h2>Encryption modes supported:</h2>
1.  AES-GCM with 2k tables<br>
2.  AES-GCM with 64k tables<br>
3.  AES-EAX<br>
4.  AES-CBC<br>
5.  AES-ECB<br>
6.  AES-CTR<br>       
7.  AES-CFB<br>
8.  AES-OFB<br>
9.  ChaCha20 (stream cipher)<br>
10. XChaCha20 (stream cipher)<br>

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

       1. To open the help book:

              Zenc -h
              Zenc -H
              Zenc

       2. To Encrypt a file: 

              Zenc -e C:\test\test.txt -m gcm2k -p Password123 -t (encrypt with a passwprd)     
              Zenc -e C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)   
              Zenc -e C:\test\test.txt -m gcm2k -np -t (generate a keyfile)
              Zenc -e C:\test\test.txt -m gcm2k -np -t -g (generate a password)

       3. To Encrypt a Directory : 

              Zenc -ed C:\test\ -m gcm2k -p Password123 - t (encrypt with a passwprd)
              Zenc -ed C:\test\ -m gcm2k -p C:\test\test.zkey -t (encrypt with a keyfile)
              Zenc -ed C:\test\ -m gcm2k -np -t (generate a keyfile)
              Zenc -ed C:\test\ -m gcm2k -np -t -g (generate a password)

       4. To Decrypt a file: 

              Zenc -d C:\test\test.txt -m gcm2k -p Password123 -t (decrypt with a passwprd)
              Zenc -d C:\test\test.txt -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)

       5. To Decrypt a Directory : 

              Zenc -dd C:\test\ -m gcm2k -p Password123 -t (decrypt with a passwprd)
              Zenc -dd C:\test\ -m gcm2k -p C:\test\test.zkey -t (decrypt with a keyfile)
       
NOTE: change Zenc according to your environment.       


