
mkdir c:\Zenc
setx path "%path%;c:\Zenc"
g++ source.cpp -std=c++17 -lcrypto++ -lstdc++fs
exit