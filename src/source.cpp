#define _CRT_SECURE_NO_WARNINGS

//HEADERS USED
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <vector>
#include <random>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/eax.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

//NAMESPACES
using namespace std;
namespace fs = std::filesystem;
using namespace CryptoPP;

//CLASSES AND STRUCTURES
//config structure (stores all the settings given by the user)
vector<string> modes = { "gcm2k","gcm64k","eax" };
struct config {
    string option;
    string fpath = "";
    string kpathPass = "";
    string mode = "";
    bool password = false;
    bool keyfile = false;
    bool genpass = false;
    bool enctitle = false;
    bool dectitle = false;
    void parseinput(int argc, char** argv) {
        //Chech the command structure and populate the config struct 
        if (argv[3][1] != 'm' && !(argv[5][1] == 'p' || (argv[5][1] == 'n' && argv[5][2] == 'p') || argv[5][1] == 't' || argv[5][1] == 'g')) {
            cout << "Improper Command Structure" << endl;
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
        option = argv[1]; //encrypt or decrypt file or folder
        if (!(option == "-e" || option == "-d" || option == "-ed" || option == "-dd")) {
            cout << "Mode not supported" << endl;
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
        fpath = argv[2]; //The File to be encrypted   
        mode = argv[4];//En/Decryption mode
        bool accept = false;//check valid mode
        for (unsigned int i = 0; i < ::modes.size(); i++) {
            if (mode == modes.at(i)) {
                accept = true;
                break;
            }
        }
        if (!accept) {// nota valid mode
            cout << "Mode not supported" << endl;
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
        if (argv[5][1] == 'p') {//If password or keyfile is mentioned
            if (argc <= 6 || argv[6][0] == '-') {
                cout << "Password not specified" << endl;
                cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                cout << "Press ENTER to continue";
                getchar();
                cout.clear();
                exit(0);
            }
            kpathPass = argv[6];//Password or path to a previous keyfile
            fs::path p(kpathPass);//check if it's a path to a keyfile
            if (fs::is_regular_file(p) && p.extension().string() == ".zkey") {//check if it is a keyfile
                password = false;
                keyfile = true;
            }
            else {//it is a password
                password = true;
                keyfile = false;
            }
            if (argc > 7) {//checks for additional options
                for (int i = 7; i < argc; i++) {
                    if (option == "-e" || option == "-ed") {
                        if (argv[i][1] == 't') {//Encrypt Titles
                            enctitle = true;
                        }
                        else {//error in input
                            cout << "Incorrect additional option used" << endl;
                            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                            cout << "Press ENTER to continue";
                            getchar();
                            cout.clear();
                            exit(0);
                        }
                    }
                    else if (option == "-d" || option == "-dd" && argv[i][1] == 't') {//decryption tools don't generate keys
                        dectitle = true;//decrypt the filenames
                    }
                    else {//error in input
                        cout << "Error in parsing command (code 1)" << endl;
                        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                        cout << "Press ENTER to continue";
                        getchar();
                        cout.clear();
                        exit(0);
                    }
                }
            }
        }
        else if (((argv[5][1] == 'n' && argv[5][2] == 'p') && option == "-e") || ((argv[5][1] == 'n' && argv[5][2] == 'p') && option == "-ed")) {//incase of decryption this will fail
            password = false;//no password was choosen so a new keyfile will be genrated 
            keyfile = false;
            genpass = true;
            if (argc > 6) {
                for (int i = 6; i < argc; i++) {//check for additional options
                    if (option == "-e" || option == "-ed") {
                        if (argv[i][1] == 't') {// encrypt with encrypted titles
                            enctitle = true;
                        }
                        else {//error in input
                            cout << "Incorrect additional option used" << endl;
                            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                            cout << "Press ENTER to continue";
                            getchar();
                            cout.clear();
                            exit(0);
                        }
                    }
                    else {//error in input
                        cout << "Error in parsing command" << endl;
                        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                        cout << "Press ENTER to continue";
                        getchar();
                        cout.clear();
                        exit(0);
                    }
                }
            }
        }
        else {//error in input
            cout << "Error in command Structure" << endl;
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
        printConfig();
    }
    void printConfig() {
        cout << ">> ZENC IMPUT:" << endl;
        cout << endl;
        cout << "Option: ";
        if (option == "-e")cout << "Encrypt File" << endl;
        else if (option == "-ed")cout << "Encrypt Folder" << endl;
        else if (option == "-d")cout << "Decrypt File" << endl;
        else if (option == "-dd")cout << "Decrypt Folder" << endl;
        cout << "Mode: " << mode << endl;
        cout << "File/Folder: " << fpath << endl;
        if (password)cout << "Password: " << kpathPass << endl;
        else if (keyfile)cout << "Keyfile Path: " << kpathPass << endl;
        else if (genpass || (!password && !keyfile))cout << "Password: A new one will be generated and displayed after encryption" << endl;
        if (enctitle)cout << "Encrypt File Names: TRUE (File names will be encrypted)" << endl;
        if (dectitle)cout << "Decrypt File Names: TRUE (File names will be decrypted) " << endl;
        cout << endl;
    }
};

//Cryptography mode classes.
class commanEncryptor {
protected:
    string randomgeniv(string password) {
        string out = "";
        minstd_rand d(password.size());
        string charset = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890*=";
        for (unsigned int i = 0; i < 16; i++) {
            int c = d() % charset.size();
            out += charset.at(c);
        }
        return out;
    }
    string randomgeniv(string password, int len) {
        string out = "";
        uint64_t rseed = 0;
        for (unsigned int i = 0; i < password.size(); i++) {
            int a = (int)password.at(i);
            rseed += (uint64_t)a;
        }
        minstd_rand d(rseed%UINT_MAX);
        string charset = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890*=";
        for (int i = 0; i < len; i++) {            
            int c = d() % charset.size();
            out += charset.at(c);
        }
        return out;
    }
    string eraseSubStr(string mainstr, string toErase) {
        size_t pos = mainstr.find(toErase);
        if (pos != std::string::npos) {
            mainstr.erase(pos, toErase.length());
        }
        return mainstr;
    }
    string getKeypath(string path) {
        fs::path p(path);
        string ext = p.extension().string();
        return eraseSubStr(path, ext);
    }
    string genEncTitle(string path) {
        fs::path f(path);
        string filename = f.filename().string();
        string encname = "";
        string password = "syIQlmMZZZUBLamI16u0lQXZuSmlVHGoctpdU44tvM9iwEDOANEO358cOh4RJLTqe8AJvEtPzvDqZ7b6UHPLY3oRgoMjiN4jvnfPwU2CqMi07OLlnNxPP3P2FBW3vrjI";
        string iv = randomgeniv(password);
        //hdkf
        SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
        HKDF<SHA256> hkdf;
        hkdf.DeriveKey(key, sizeof(key), (const unsigned char*)password.data(), password.size(),
            (const unsigned char*)iv.data(), iv.size(), NULL, 0);

        GCM<AES, GCM_2K_Tables>::Encryption e;
        e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
        StringSource f1(filename, true,
            new AuthenticatedEncryptionFilter(e,
                new StringSink(encname)));
        return encname + ".Zenc";
    }
    string genDecTitle(string path) {
        fs::path f(path);
        string filename = f.filename().string();
        filename = eraseSubStr(filename, ".Zenc");
        string decname = "";
        string password = "syIQlmMZZZUBLamI16u0lQXZuSmlVHGoctpdU44tvM9iwEDOANEO358cOh4RJLTqe8AJvEtPzvDqZ7b6UHPLY3oRgoMjiN4jvnfPwU2CqMi07OLlnNxPP3P2FBW3vrjI";
        string iv = randomgeniv(password);
        //hdkf
        SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
        HKDF<SHA256> hkdf;
        hkdf.DeriveKey(key, sizeof(key), (const unsigned char*)password.data(), password.size(),
            (const unsigned char*)iv.data(), iv.size(), NULL, 0);

        GCM<AES, GCM_2K_Tables>::Decryption d;
        d.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
        StringSource f2(filename, true,
            new AuthenticatedDecryptionFilter(d,
                new StringSink(decname)));
        return decname;
    }
};
class gcm2k : commanEncryptor
{
private:
    GCM<AES, GCM_2K_Tables>::Encryption e;
    GCM<AES, GCM_2K_Tables>::Decryption d;
    config settings;
    bool delFile = false;
    void regenpass() {
        if (settings.password == true) {
            genKeyFromPass();
        }
        else if (settings.keyfile == true) {
            loadKeyFromFile();
        }
        else if (settings.genpass == true) {
            genKeyFile();
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void genKeyFromPass() {
        try {
            string password = settings.kpathPass;
            string iv = randomgeniv(password);
            //hdkf
            SecByteBlock key(AES::MAX_KEYLENGTH + AES::BLOCKSIZE);
            HKDF<SHA256> hkdf;
            string filepath = settings.fpath;
            fs::path f(filepath);
            if (f.extension().string() == ".Zenc")
                filepath = eraseSubStr(filepath, ".Zenc");
            hkdf.DeriveKey(key, sizeof(key), (const unsigned char*)password.data(), password.size(),
                (const unsigned char*)iv.data(), iv.size(), (const unsigned char*)filepath.c_str(), filepath.size());
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
            else {
                d.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key + AES::MAX_KEYLENGTH);
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error generating key from password\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void loadKeyFromFile() {
        try {
            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE];
            fstream rk(settings.kpathPass, ios::in | ios::binary);
            rk.read((char*)key, sizeof(key));
            rk.read((char*)iv, sizeof(iv));
            rk.close();
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error loading key from key file\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void genKeyFile() {
        try {
            AutoSeededRandomPool prng;
            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            prng.GenerateBlock(key, sizeof(key));
            CryptoPP::byte iv[AES::BLOCKSIZE];
            prng.GenerateBlock(iv, sizeof(iv));
            string kpath = getKeypath(settings.fpath);
            try {
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                writek.close();
            }
            catch (...) {
                cout << "Error writing key file\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error generating key file\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void encryptFile() {
        try {
            while (true) {
                cout << "Delete Orignal Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string encpath;
            if (settings.enctitle) {
                encpath = genEncTitle(settings.fpath);
            }
            else {
                encpath = settings.fpath + ".Zenc";
            }

            FileSource f(settings.fpath.c_str(), true,
                new AuthenticatedEncryptionFilter(e,
                    new FileSink(encpath.c_str())));
            if (delFile) {
                if (remove(settings.fpath.c_str()) == 0) {
                }
                else {
                    cout << "Cannot Delete File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                }
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Cannot Encrypt File:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void decryptFile() {
        try {
            while (true) {
                cout << "Delete Orignal Encrypted Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string checkpath = settings.fpath;
            fs::path check(checkpath);
            if (check.extension().string() != ".Zenc") {
                cout << "Cannot Decrypt File:" << settings.fpath << endl;
                cout << "ERROR: File not encrypted with Zenc" << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            string decpath;
            if (settings.dectitle) {
                decpath = genDecTitle(settings.fpath);
            }
            else {
                decpath = eraseSubStr(settings.fpath, ".Zenc");
            }

            FileSource f(settings.fpath.c_str(), true,
                new AuthenticatedDecryptionFilter(d,
                    new FileSink(decpath.c_str())));
            if (delFile) {
                if (remove(settings.fpath.c_str()) == 0) {
                }
                else {
                    cout << "Cannot Delete File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                }
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Cannot Decrypt File:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }

    }
    void encryptFolder() {
        try {
            while (true) {
                cout << "Delete Orignal Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string encpath;
            fs::path encdir(settings.fpath);
            if (!fs::is_directory(encdir)) {
                cout << "This is not a Director:" << settings.fpath << endl;
                cout << "ERROR: " << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            for (auto& file : fs::recursive_directory_iterator(encdir)) {
                try {
                    string filepath = file.path().string();
                    if (settings.enctitle) {
                        encpath = genEncTitle(filepath);
                    }
                    else {
                        encpath = file.path().string() + ".Zenc";
                    }
                    FileSource f(filepath.c_str(), true,
                        new AuthenticatedEncryptionFilter(e,
                            new FileSink(encpath.c_str())));
                    regenpass();
                    if (delFile) {
                        if (remove(filepath.c_str()) == 0) {
                            continue;
                        }
                        else {
                            cout << "Cannot Delete File:" << settings.fpath << endl;
                            cout << "ERROR: " << strerror(errno) << endl;
                            while (true) {
                                cout << "Continue? [y/n]\t";
                                char ch;
                                cin >> ch;
                                if (ch == 'y' || ch == 'Y') {
                                    break;
                                }
                                else if (ch == 'n' || ch == 'N') {
                                    cout << "Press ENTER to Exit ...";
                                    getchar();
                                    exit(EXIT_FAILURE);
                                }
                                else {
                                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (CryptoPP::Exception& e)
                {
                    cerr << "Caught Exception..." << endl;
                    cerr << e.what() << endl;
                    cerr << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                catch (...) {
                    cout << "Cannot Encrypt File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
            }
        }
        catch (...) {
            cout << "Cannot Encrypt Directory:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void decryptFolder() {
        try {
            while (true) {
                cout << "Delete Orignal Encrypted Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string decpath;
            fs::path encdir(settings.fpath);
            if (!fs::is_directory(encdir)) {
                cout << "This is not a Director:" << settings.fpath << endl;
                cout << "ERROR: " << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            for (auto& file : fs::recursive_directory_iterator(encdir)) {
                if (file.path().extension().string() != ".Zenc") {
                    cout << "Cannot Decrypt File:" << settings.fpath << endl;
                    cout << "ERROR: File not encrypted with Zenc" << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                try {
                    string filepath = file.path().string();
                    if (settings.dectitle) {
                        decpath = genDecTitle(filepath);
                    }
                    else {
                        decpath = eraseSubStr(filepath, ".Zenc");
                    }
                    FileSource f(filepath.c_str(), true,
                        new AuthenticatedDecryptionFilter(d,
                            new FileSink(decpath.c_str())));
                    regenpass();
                    if (delFile) {
                        if (remove(filepath.c_str()) == 0) {
                            continue;
                        }
                        else {
                            cout << "Cannot Delete File:" << settings.fpath << endl;
                            cout << "ERROR: " << strerror(errno) << endl;
                            while (true) {
                                cout << "Continue? [y/n]\t";
                                char ch;
                                cin >> ch;
                                if (ch == 'y' || ch == 'Y') {
                                    break;
                                }
                                else if (ch == 'n' || ch == 'N') {
                                    cout << "Press ENTER to Exit ...";
                                    getchar();
                                    exit(EXIT_FAILURE);
                                }
                                else {
                                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (CryptoPP::Exception& e)
                {
                    cerr << "Caught Exception..." << endl;
                    cerr << e.what() << endl;
                    cerr << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                catch (...) {
                    cout << "Cannot Encrypt File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
            }
        }
        catch (...) {
            cout << "Cannot Encrypt Directory:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
public:
    void init(config c) {
        settings = c;
        string fp = settings.fpath;
        fs::path f(fp);
        if (f.extension().string() == ".Zenc" && (settings.option == "-e" || settings.option == "-ed")) {
            cout << "File Already Encrypted" << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        if (settings.password == true) {
            genKeyFromPass();
        }
        else if (settings.keyfile == true) {
            loadKeyFromFile();
        }
        else if (settings.genpass == true) {
            genKeyFile();
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        if (settings.option == "-e" || settings.option == "-ed") {
            if (settings.option == "-e") {
                encryptFile();
            }
            else if (settings.option == "-ed") {
                encryptFolder();
            }
            else {
                cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
        }
        else if (settings.option == "-d" || settings.option == "-dd") {
            if (settings.option == "-d") {
                decryptFile();
            }
            else if (settings.option == "-dd") {
                decryptFolder();
            }
            else {
                cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }

};
class gcm64k : commanEncryptor
{
private:
    GCM<AES, GCM_64K_Tables>::Encryption e;
    GCM<AES, GCM_64K_Tables>::Decryption d;
    config settings;
    bool delFile = false;
    void regenpass() {
        if (settings.password == true) {
            genKeyFromPass();
        }
        else if (settings.keyfile == true) {
            loadKeyFromFile();
        }
        else if (settings.genpass == true) {
            genKeyFile();
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void genKeyFromPass() {
        try {
            string password = settings.kpathPass;
            string iv = randomgeniv(password);
            //hdkf
            SecByteBlock key(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE);
            HKDF<SHA256> hkdf;
            string filepath = settings.fpath;
            fs::path f(filepath);
            if (f.extension().string() == ".Zenc")
                filepath = eraseSubStr(filepath, ".Zenc");
            hkdf.DeriveKey(key, sizeof(key), (const unsigned char*)password.data(), password.size(),
                (const unsigned char*)iv.data(), iv.size(), (const unsigned char*)filepath.c_str(), filepath.size());
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, key + AES::DEFAULT_KEYLENGTH);
            }
            else {
                d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, key + AES::DEFAULT_KEYLENGTH);
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error generating key from password\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void loadKeyFromFile() {
        try {
            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE];
            fstream rk(settings.kpathPass, ios::in | ios::binary);
            rk.read((char*)key, sizeof(key));
            rk.read((char*)iv, sizeof(iv));
            rk.close();
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error loading key from key file\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void genKeyFile() {
        try {
            AutoSeededRandomPool prng;
            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            prng.GenerateBlock(key, sizeof(key));
            CryptoPP::byte iv[AES::BLOCKSIZE];
            prng.GenerateBlock(iv, sizeof(iv));
            string kpath = getKeypath(settings.fpath);
            try {
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                writek.close();
            }
            catch (...) {
                cout << "Error writing key file\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key),iv,sizeof(iv));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error generating key file\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void encryptFile() {
        try {
            while (true) {
                cout << "Delete Orignal Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string encpath;
            if (settings.enctitle) {
                encpath = genEncTitle(settings.fpath);
            }
            else {
                encpath = settings.fpath + ".Zenc";
            }

            FileSource f(settings.fpath.c_str(), true,
                new AuthenticatedEncryptionFilter(e,
                    new FileSink(encpath.c_str())));
            if (delFile) {
                if (remove(settings.fpath.c_str()) == 0) {
                }
                else {
                    cout << "Cannot Delete File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                }
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Cannot Encrypt File:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void decryptFile() {
        try {
            while (true) {
                cout << "Delete Orignal Encrypted Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string checkpath = settings.fpath;
            fs::path check(checkpath);
            if (check.extension().string() != ".Zenc") {
                cout << "Cannot Decrypt File:" << settings.fpath << endl;
                cout << "ERROR: File not encrypted with Zenc" << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            string decpath;
            if (settings.dectitle) {
                decpath = genDecTitle(settings.fpath);
            }
            else {
                decpath = eraseSubStr(settings.fpath, ".Zenc");
            }
            FileSource f(settings.fpath.c_str(), true,
                new AuthenticatedDecryptionFilter(d,
                    new FileSink(decpath.c_str())));
            if (delFile) {
                if (remove(settings.fpath.c_str()) == 0) {
                }
                else {
                    cout << "Cannot Delete File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                }
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Cannot Decrypt File:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }

    }
    void encryptFolder() {
        try {
            while (true) {
                cout << "Delete Orignal Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string encpath;
            fs::path encdir(settings.fpath);
            if (!fs::is_directory(encdir)) {
                cout << "This is not a Director:" << settings.fpath << endl;
                cout << "ERROR: " << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            for (auto& file : fs::recursive_directory_iterator(encdir)) {
                try {
                    string filepath = file.path().string();
                    if (settings.enctitle) {
                        encpath = genEncTitle(filepath);
                    }
                    else {
                        encpath = file.path().string() + ".Zenc";
                    }
                    FileSource f(filepath.c_str(), true,
                        new AuthenticatedEncryptionFilter(e,
                            new FileSink(encpath.c_str())));
                    regenpass();
                    if (delFile) {
                        if (remove(filepath.c_str()) == 0) {
                            continue;
                        }
                        else {
                            cout << "Cannot Delete File:" << settings.fpath << endl;
                            cout << "ERROR: " << strerror(errno) << endl;
                            while (true) {
                                cout << "Continue? [y/n]\t";
                                char ch;
                                cin >> ch;
                                if (ch == 'y' || ch == 'Y') {
                                    break;
                                }
                                else if (ch == 'n' || ch == 'N') {
                                    cout << "Press ENTER to Exit ...";
                                    getchar();
                                    exit(EXIT_FAILURE);
                                }
                                else {
                                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (CryptoPP::Exception& e)
                {
                    cerr << "Caught Exception..." << endl;
                    cerr << e.what() << endl;
                    cerr << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                catch (...) {
                    cout << "Cannot Encrypt File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
            }
        }
        catch (...) {
            cout << "Cannot Encrypt Directory:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void decryptFolder() {
        try {
            while (true) {
                cout << "Delete Orignal Encrypted Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string decpath;
            fs::path encdir(settings.fpath);
            if (!fs::is_directory(encdir)) {
                cout << "This is not a Director:" << settings.fpath << endl;
                cout << "ERROR: " << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            for (auto& file : fs::recursive_directory_iterator(encdir)) {
                if (file.path().extension().string() != ".Zenc") {
                    cout << "Cannot Decrypt File:" << settings.fpath << endl;
                    cout << "ERROR: File not encrypted with Zenc" << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                try {
                    string filepath = file.path().string();
                    if (settings.dectitle) {
                        decpath = genDecTitle(filepath);
                    }
                    else {
                        decpath = eraseSubStr(filepath, ".Zenc");
                    }
                    FileSource f(filepath.c_str(), true,
                        new AuthenticatedDecryptionFilter(d,
                            new FileSink(decpath.c_str())));
                    regenpass();
                    if (delFile) {
                        if (remove(filepath.c_str()) == 0) {
                            continue;
                        }
                        else {
                            cout << "Cannot Delete File:" << settings.fpath << endl;
                            cout << "ERROR: " << strerror(errno) << endl;
                            while (true) {
                                cout << "Continue? [y/n]\t";
                                char ch;
                                cin >> ch;
                                if (ch == 'y' || ch == 'Y') {
                                    break;
                                }
                                else if (ch == 'n' || ch == 'N') {
                                    cout << "Press ENTER to Exit ...";
                                    getchar();
                                    exit(EXIT_FAILURE);
                                }
                                else {
                                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (CryptoPP::Exception& e)
                {
                    cerr << "Caught Exception..." << endl;
                    cerr << e.what() << endl;
                    cerr << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                catch (...) {
                    cout << "Cannot Encrypt File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
            }
        }
        catch (...) {
            cout << "Cannot Encrypt Directory:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
public:
    void init(config c) {
        settings = c;
        string fp = settings.fpath;
        fs::path f(fp);
        if (f.extension().string() == ".Zenc" && (settings.option == "-e" || settings.option == "-ed")) {
            cout << "File Already Encrypted" << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        if (settings.password == true) {
            genKeyFromPass();
        }
        else if (settings.keyfile == true) {
            loadKeyFromFile();
        }
        else if (settings.genpass == true) {
            genKeyFile();
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        if (settings.option == "-e" || settings.option == "-ed") {
            if (settings.option == "-e") {
                encryptFile();
            }
            else if (settings.option == "-ed") {
                encryptFolder();
            }
            else {
                cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
        }
        else if (settings.option == "-d" || settings.option == "-dd") {
            if (settings.option == "-d") {
                decryptFile();
            }
            else if (settings.option == "-dd") {
                decryptFolder();
            }
            else {
                cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
};
class eax : commanEncryptor
{
private:
    EAX< AES >::Encryption e;
    EAX< AES >::Decryption d;
    config settings;
    bool delFile = false;
    void regenpass() {
        if (settings.password == true) {
            genKeyFromPass();
        }
        else if (settings.keyfile == true) {
            loadKeyFromFile();
        }
        else if (settings.genpass == true) {
            genKeyFile();
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void genKeyFromPass() {
        try {
            string password = settings.kpathPass;
            string iv = randomgeniv(password, AES::BLOCKSIZE * 16);
            //hdkf
            SecByteBlock key(AES::DEFAULT_KEYLENGTH);
            HKDF<SHA256> hkdf;
            string filepath = settings.fpath;
            fs::path f(filepath);
            if (f.extension().string() == ".Zenc")
                filepath = eraseSubStr(filepath, ".Zenc");
            hkdf.DeriveKey(key, sizeof(key), (const unsigned char*)password.data(), password.size(),
                (const unsigned char*)iv.data(), iv.size(), (const unsigned char*)filepath.c_str(), filepath.size());
           
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key),(const unsigned char*)iv.c_str(),sizeof((const unsigned char*)iv.c_str()));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), (const unsigned char*)iv.c_str(), sizeof((const unsigned char*)iv.c_str()));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error generating key from password\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void loadKeyFromFile() {
        try {
            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            CryptoPP::byte iv[AES::BLOCKSIZE*16];
            fstream rk(settings.kpathPass, ios::in | ios::binary);
            rk.read((char*)key, sizeof(key));
            rk.read((char*)iv, sizeof(iv));
            rk.close();
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error loading key from key file\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void genKeyFile() {
        try {
            AutoSeededRandomPool prng;
            CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
            prng.GenerateBlock(key, sizeof(key));
            CryptoPP::byte iv[AES::BLOCKSIZE*16];
            prng.GenerateBlock(iv, sizeof(iv));
            string kpath = getKeypath(settings.fpath);
            try {
                fstream writek(kpath, ios::out | ios::binary);
                writek.write((char*)key, sizeof(key));
                writek.write((char*)iv, sizeof(iv));
                writek.close();
            }
            catch (...) {
                cout << "Error writing key file\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            if (settings.option == "-e" || settings.option == "-ed") {
                e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
            else {
                d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Error generating key file\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void encryptFile() {
        try {
            while (true) {
                cout << "Delete Orignal Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string encpath;
            if (settings.enctitle) {
                encpath = genEncTitle(settings.fpath);
            }
            else {
                encpath = settings.fpath + ".Zenc";
            }

            FileSource f(settings.fpath.c_str(), true,
                new AuthenticatedEncryptionFilter(e,
                    new FileSink(encpath.c_str())));
            if (delFile) {
                if (remove(settings.fpath.c_str()) == 0) {
                }
                else {
                    cout << "Cannot Delete File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                }
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Cannot Encrypt File:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void decryptFile() {
        try {
            while (true) {
                cout << "Delete Orignal Encrypted Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string checkpath = settings.fpath;
            fs::path check(checkpath);
            if (check.extension().string() != ".Zenc") {
                cout << "Cannot Decrypt File:" << settings.fpath << endl;
                cout << "ERROR: File not encrypted with Zenc" << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            string decpath;
            if (settings.dectitle) {
                decpath = genDecTitle(settings.fpath);
            }
            else {
                decpath = eraseSubStr(settings.fpath, ".Zenc");
            }
            FileSource f(settings.fpath.c_str(), true,
                new AuthenticatedDecryptionFilter(d,
                    new FileSink(decpath.c_str())));
            if (delFile) {
                if (remove(settings.fpath.c_str()) == 0) {
                }
                else {
                    cout << "Cannot Delete File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                }
            }
        }
        catch (CryptoPP::Exception& e)
        {
            cerr << "Caught Exception..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        catch (...) {
            cout << "Cannot Decrypt File:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }

    }
    void encryptFolder() {
        try {
            while (true) {
                cout << "Delete Orignal Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string encpath;
            fs::path encdir(settings.fpath);
            if (!fs::is_directory(encdir)) {
                cout << "This is not a Director:" << settings.fpath << endl;
                cout << "ERROR: " << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            for (auto& file : fs::recursive_directory_iterator(encdir)) {
                try {
                    string filepath = file.path().string();
                    if (settings.enctitle) {
                        encpath = genEncTitle(filepath);
                    }
                    else {
                        encpath = file.path().string() + ".Zenc";
                    }
                    FileSource f(filepath.c_str(), true,
                        new AuthenticatedEncryptionFilter(e,
                            new FileSink(encpath.c_str())));
                    regenpass();
                    if (delFile) {
                        if (remove(filepath.c_str()) == 0) {
                            continue;
                        }
                        else {
                            cout << "Cannot Delete File:" << settings.fpath << endl;
                            cout << "ERROR: " << strerror(errno) << endl;
                            while (true) {
                                cout << "Continue? [y/n]\t";
                                char ch;
                                cin >> ch;
                                if (ch == 'y' || ch == 'Y') {
                                    break;
                                }
                                else if (ch == 'n' || ch == 'N') {
                                    cout << "Press ENTER to Exit ...";
                                    getchar();
                                    exit(EXIT_FAILURE);
                                }
                                else {
                                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (CryptoPP::Exception& e)
                {
                    cerr << "Caught Exception..." << endl;
                    cerr << e.what() << endl;
                    cerr << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                catch (...) {
                    cout << "Cannot Encrypt File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
            }
        }
        catch (...) {
            cout << "Cannot Encrypt Directory:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
    void decryptFolder() {
        try {
            while (true) {
                cout << "Delete Orignal Encrypted Files? [y/n]\t";
                char ch;
                cin >> ch;
                if (ch == 'y' || ch == 'Y') {
                    delFile = true;
                    break;
                }
                else if (ch == 'n' || ch == 'N') {
                    delFile = false;
                    break;
                }
                else {
                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                }
            }
            string decpath;
            fs::path encdir(settings.fpath);
            if (!fs::is_directory(encdir)) {
                cout << "This is not a Director:" << settings.fpath << endl;
                cout << "ERROR: " << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
            for (auto& file : fs::recursive_directory_iterator(encdir)) {
                if (file.path().extension().string() != ".Zenc") {
                    cout << "Cannot Decrypt File:" << settings.fpath << endl;
                    cout << "ERROR: File not encrypted with Zenc" << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                try {
                    string filepath = file.path().string();
                    if (settings.dectitle) {
                        decpath = genDecTitle(filepath);
                    }
                    else {
                        decpath = eraseSubStr(filepath, ".Zenc");
                    }
                    FileSource f(filepath.c_str(), true,
                        new AuthenticatedDecryptionFilter(d,
                            new FileSink(decpath.c_str())));
                    regenpass();
                    if (delFile) {
                        if (remove(filepath.c_str()) == 0) {
                            continue;
                        }
                        else {
                            cout << "Cannot Delete File:" << settings.fpath << endl;
                            cout << "ERROR: " << strerror(errno) << endl;
                            while (true) {
                                cout << "Continue? [y/n]\t";
                                char ch;
                                cin >> ch;
                                if (ch == 'y' || ch == 'Y') {
                                    break;
                                }
                                else if (ch == 'n' || ch == 'N') {
                                    cout << "Press ENTER to Exit ...";
                                    getchar();
                                    exit(EXIT_FAILURE);
                                }
                                else {
                                    cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (CryptoPP::Exception& e)
                {
                    cerr << "Caught Exception..." << endl;
                    cerr << e.what() << endl;
                    cerr << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
                catch (...) {
                    cout << "Cannot Encrypt File:" << settings.fpath << endl;
                    cout << "ERROR: " << strerror(errno) << endl;
                    while (true) {
                        cout << "Continue? [y/n]\t";
                        char ch;
                        cin >> ch;
                        if (ch == 'y' || ch == 'Y') {
                            break;
                        }
                        else if (ch == 'n' || ch == 'N') {
                            cout << "Press ENTER to Exit ...";
                            getchar();
                            exit(EXIT_FAILURE);
                        }
                        else {
                            cout << "Invalidd Input type y or Y for Yes or n or N for No\n";
                        }
                    }
                    continue;
                }
            }
        }
        catch (...) {
            cout << "Cannot Encrypt Directory:" << settings.fpath << endl;
            cout << "ERROR: " << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
public:
    void init(config c) {
        settings = c;
        string fp = settings.fpath;
        fs::path f(fp);
        if (f.extension().string() == ".Zenc" && (settings.option == "-e" || settings.option == "-ed")) {
            cout << "File Already Encrypted" << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        if (settings.password == true) {
            genKeyFromPass();
        }
        else if (settings.keyfile == true) {
            loadKeyFromFile();
        }
        else if (settings.genpass == true) {
            genKeyFile();
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
        if (settings.option == "-e" || settings.option == "-ed") {
            if (settings.option == "-e") {
                encryptFile();
            }
            else if (settings.option == "-ed") {
                encryptFolder();
            }
            else {
                cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
        }
        else if (settings.option == "-d" || settings.option == "-dd") {
            if (settings.option == "-d") {
                decryptFile();
            }
            else if (settings.option == "-dd") {
                decryptFolder();
            }
            else {
                cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
                cout << "Press ENTER to Exit ...";
                getchar();
                exit(EXIT_FAILURE);
            }
        }
        else {
            cout << "Error Invalid Configuration\n" << strerror(errno) << endl;
            cout << "Press ENTER to Exit ...";
            getchar();
            exit(EXIT_FAILURE);
        }
    }
};

//MISC FUNCTIONS
void help() {
    cout << "::: Zenc HELPBOOK :::" << endl;
    cout << "Zenc <OPTIONS/TO ENCRYPT A FILE/TO ENCRYPT A FOLDER/TO DECRYPT A FILE/TO DECRYPT A FOLDER>\n";
    cout << endl;
    cout << "$$$$ OPTIONS $$$$\n\n";
    cout << "$ FOR HELP \n";
    cout << "- h or -H\tOPEN HELPBOOK\n ";
    cout << endl;
    cout << "$$$$ FOR ENCRYPTING $$$";
    cout << endl;
    cout << "\n$ TO ENCRYPT A FILE" << endl;
    cout << "-e <filepath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-e\t\tTo encrypt a file." << endl;
    cout << "<filepath>\tPath to the file to be encrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "\t1. gcm2k\tGCM with 2K tables" << endl;
    cout << "\t2. gcm64k\tGCM with 64k tables" << endl;
    cout << "\t3. eax\t\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tIf you want to enter the <password> or the <path> to an existing .key file" << endl;
    cout << "-np\t\tIf you don;t want to specify a password then a new .key file will be genrated in the same directory";
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tEncrypts the name of the Files also" << endl;

    cout << endl;
    cout << "\n$ TO ENCRYPT A DIR" << endl;
    cout << "-ed <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-ed\t\tTo encrypt a dir." << endl;
    cout << "<folderpath>\tPath to the file to be encrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "\t1. gcm2k\tGCM with 2K tables" << endl;
    cout << "\t2. gcm64k\tGCM with 64k tables" << endl;
    cout << "\t3. eax\t\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tIf you want to enter the <password> or the <path> to an existing .key file" << endl;
    cout << "-np\t\tIf you don;t want to specify a password then a new .key file will be genrated in the same directory";
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tEncrypts the name of the Files also" << endl;

    cout << endl;
    cout << "$$$$ FOR DECRYPTING $$$$" << endl;
    cout << endl;
    cout << "\n$ TO DECRYPT A FILE" << endl;
    cout << "-d <filepath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-d\t\tTo decrypt a file." << endl;
    cout << "<filepath>\tPath to the file to be decrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion used" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "\t1. gcm2k\tGCM with 2K tables" << endl;
    cout << "\t2. gcm64k\tGCM with 64k tables" << endl;
    cout << "\t3. eax\t\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tPassword used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption" << endl;
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tMention this if the file names were encrypted" << endl;

    cout << endl;
    cout << "\n$ TO DECRYPT A FOLDER" << endl;
    cout << "-dd <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-dd\t\tTo decrypt a dir." << endl;
    cout << "<folderpath>\tPath to the file to be decrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion used" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "\t1. gcm2k\tGCM with 2K tables" << endl;
    cout << "\t2. gcm64k\tGCM with 64k tables" << endl;
    cout << "\t3. eax\t\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tPassword used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption" << endl;
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tMention this if the file names were encrypted" << endl;
    cout << endl;
}

//FUNCTIONS
bool encryptfile(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        gcm2k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "gcm64k") {
        gcm64k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "eax") {
        eax a;
        a.init(c);
        return true;
    }
    return false;
}
bool encryptfolder(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        gcm2k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "gcm64k") {
        gcm64k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "eax") {
        eax a;
        a.init(c);
        return true;
    }
    return false;
}
bool decryptfile(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        gcm2k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "gcm64k") {
        gcm64k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "eax") {
        eax a;
        a.init(c);
        return true;
    }
    return false;
}
bool decryptfolder(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    if (c.mode == "gcm2k") {
        gcm2k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "gcm64k") {
        gcm64k a;
        a.init(c);
        return true;
    }
    else if (c.mode == "eax") {
        eax a;
        a.init(c);
        return true;
    }
    return false;
}

//MAIN FUNCTION
int main(int argc, char** argv)
{
    if (argc == 1) {
        help();
        exit(EXIT_FAILURE);
    }
    config c;
    //Check the option being used ie -h/-H or -e or -ed or -d or -dd
    string option = argv[1];
    //if option was for help
    if (option == "-h" || option == "-H") {
        cout << "Loading Helpbook ..." << endl;
        help();
        return 0;
    }
    //if -e
    else if (option == "-e") {
        if (!encryptfile(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
        else {
            cout << endl;
            cout << "DONE";
        }
    }
    //if -ed
    else if (option == "-ed") {
        if (!encryptfolder(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
        else {
            cout << endl;
            cout << "DONE";
        }
    }
    //if -d
    else if (option == "-d") {
        if (!decryptfile(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
        else {
            cout << endl;
            cout << "DONE";
        }
    }
    //if -dd
    else if (option == "-dd") {
        if (!decryptfolder(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
        else {
            cout << endl;
            cout << "DONE";
        }
    }
    //wrong input
    else {
        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
        cout << "Press ENTER to continue";
        getchar();
        cout.clear();
        exit(0);
    }
}

