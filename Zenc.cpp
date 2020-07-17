#define _CRT_SECURE_NO_WARNINGS

//HEADERS USED
#include <iostream>
#include <string>
#include <filesystem>
#include <vector>

//NAMESPACES
using namespace std;
namespace fs = std::filesystem;

//STRUCTURES
struct config {
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
        fpath = argv[2]; //The File to be encrypted
        if (argv[3] != "-m") { //Incorrect input format
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
        else {
            mode = argv[4];//En/Decryption mode
        }
        if (argv[5] == "-p") {//If password or keyfile is mentioned
            kpathPass = argv[6];//Password or path to a previous keyfile
            fs::path p(kpathPass);//check if it's a path to a keyfile
            if (fs::is_regular_file(p) && p.extension().string()==".zkey") {//check if it is a keyfile
                password = false;
                keyfile = true;
            }
            else {//it is a password
                password = true;
                keyfile = false;
            }            
            if (argc > 7) {//checks for additional options
                for (int i = 7; i <= argc; i++) {
                    if (argv[1] == "-e" || argv[1] == "-ed") {
                        if (argv[i] == "-t") {//Encrypt Titles
                            enctitle = true;
                        }
                        else if (argv[i] == "-g") {//Generate a random password
                            genpass = true;
                        }
                        else {//error in input
                            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                            cout << "Press ENTER to continue";
                            getchar();
                            cout.clear();
                            exit(0);
                        }
                    }
                    else if (argv[1] == "-d" || argv[1] == "-dd" && argv[i] == "-t") {//decryption tools don't generate keys
                        dectitle = true;//decrypt the filenames
                    }                        
                    else {//error in input
                        cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                        cout << "Press ENTER to continue";
                        getchar();
                        cout.clear();
                        exit(0);
                    }
                }
            }
        }
        else if ((argv[5] == "-np" || argv[1]=="-e")|| (argv[5] == "-np" || argv[1] == "-ed")) {//incase of decryption this will fail
            password = false;//no password was choosen so a new keyfile will be genrated 
            keyfile = false;
            if (argc > 6) {
                for (int i = 6; i <= argc; i++) {//check for additional options
                    if (argv[1] == "-e" || argv[1] == "-ed") {
                        if (argv[i] == "-t") {// encrypt with encrypted titles
                            enctitle = true;
                        }
                        else if (argv[i] == "-g") {// generate a password
                            genpass = true;
                        }
                        else {//error in input
                            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
                            cout << "Press ENTER to continue";
                            getchar();
                            cout.clear();
                            exit(0);
                        }
                    }
                    else if (argv[1] == "-d" || argv[1] == "-dd" && argv[i] == "-t") {// decrypt title
                        dectitle = true;//decrypt the filenames
                    }                        
                    else {//error in input
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
            cout << "ERROR IN IMPUT CHECK THE HELPBOOK USING Zenc -h or Zenc -H" << endl;
            cout << "Press ENTER to continue";
            getchar();
            cout.clear();
            exit(0);
        }
    }    
};


//MISC FUNCTIONS
void help() {
    cout << "::: Zenc HELPBOOK :::" << endl;
    cout << "Zenc <options>\n";
    cout << endl;
    cout << "OPTIONS:\n\n";
    cout << "$ FOR HELP \n";
    cout << "- h or -H\t\t OPEN HELPBOOK\n ";
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
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tIf you want to enter the <password> or the <path> to an existing .key file" << endl;
    cout << "-np\t\tIf you don;t want to specify a password then a new .key file will be genrated in the same directory";
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tEncrypts the name of the Files also" << endl;
    cout << "-g\t\tGenerates a random password for the file" << endl;

    cout << endl;
    cout << "\n$ TO ENCRYPT A DIR" << endl;
    cout << "-ed <folderpath> -m <mode> -p <password/key path> / -np -<additional_options>" << endl;
    cout << endl;
    cout << "-ed\t\tTo encrypt a dir." << endl;
    cout << "<folderpath>\tPath to the file to be encrypted" << endl;
    cout << "-m\t\tChoose the mode of encrytion" << endl;
    cout << endl;
    cout << "MODES SUPPORTED:\n";//add modes
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tIf you want to enter the <password> or the <path> to an existing .key file" << endl;
    cout << "-np\t\tIf you don;t want to specify a password then a new .key file will be genrated in the same directory";
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tEncrypts the name of the Files also" << endl;
    cout << "-g\t\tGenerates a random password for the file" << endl;

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
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
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
    cout << "1. gcm2k\tGCM with 2K tables" << endl;
    cout << "2. gcm64k\tGCM with 64k tables" << endl;
    cout << "3. ccm\tCCM mode" << endl;
    cout << "4. eax\tEAX mode" << endl;
    cout << endl;
    cout << "-p\t\tPassword used to encrypt the file if no password was used while encrypting then give the path to the .key file generated at the point of encryption" << endl;
    cout << "ADDITIONAL OPTIONS:" << endl;
    cout << "-t\t\tMention this if the file names were encrypted" << endl;
}

//FUNCTIONS
bool encryptfile(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    
    //setup password
    if (c.password) {
        //hdkf
    }
    else if (c.keyfile) {
        //inputkey
    }
    else {
        //generate a keyfile
    }
    //encrypt the files
    //encrypt titles if asked
    return true;
}
bool encryptfolder(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    //setup password
    //start a dir iterator
        //encrypt the files
        //encrypt titles if asked
    return true;
}
bool decryptfile(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    //setup password
    //decrypt the file
    //decrypt the filename
    return true;
}
bool decryptfolder(int argc, char** argv) {
    config c;
    c.parseinput(argc, argv);
    //check mode
    //setup password
    //start a dir iterator
        //decrypt the file
        //decrypt the filename
    return true;
}

//MAIN FUNCTION
int main(int argc, char** argv)
{
    //Check the option being used ie -h/-H or -e or -ed or -d or -dd
    string option = argv[1];
    //if option was for help
    if (option == "-h" || option == "-H") {
        help();
        return 0;
    }
    //if -e
    else if (option == "-e") {
        if (!encryptfile(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //if -ed
    else if (option == "-ed") {
        if (!encryptfolder(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //if -d
    else if (option == "-d") {
        if (!decryptfile(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
        }
    }
    //if -dd
    else if (option == "-dd") {
        if (!decryptfolder(argc, argv)) {
            cout << "\nAn ERROR has occoured\n" << strerror(errno);
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

