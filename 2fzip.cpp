/*
 * 2Factor Zip Copyright (c) 2014 Kyle Koceski
 * A program for providing 2-Factor authentication to *.zip files via SMS
 * (via TextBelt API: http://www.textbelt.com) at compression time.
 */

#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sstream>
#include <fstream>
#include <fcntl.h>
#include <sys/stat.h>

//Patches a C++11 to_string()
namespace patch {
	template<typename T> std::string to_string(const T& n) {
		std::ostringstream stm;
		stm << n;
		return stm.str();
	}
}

using namespace std;

//CONSTANTS
const string ZIP = "zip";
const string UNZIP = "unzip";
const string TEXTBELT_URL = "http://textbelt.com/text";
const int MIN_ARG_COUNT = 4;//2fzip -d pwd zipfile

//the authentication code, generated is parseArgs and used for the zipCmd and textCmd
string theAuthCode;

//Methods for fork()ing the process to generate the zip, text, and revert the zip-generation transaction
bool generateZip(char** zipCmd);
bool generateText(string authCode, string phoneNum, string filename);
void undoGenerateZip(string zipName);

//Prints the proper usage of 2fzip when improper command arguments are provided
void helpMenu() {
	cout << "2Factor Zip Copyright (c) 2014 Kyle Koceski" << endl;
	cout << "Usage:" << endl;
	cout << "  2fzip -e password [zip_parameters] zipfilename.2fz filelist" << endl;
	//         zip -P code:password [zip_parameters] zipfilename.2fz filelist
	cout << "  2fzip -d password [unzip_parameters] zipfilename.2fz" << endl;
	//         unzip -P code:password [unzip_parameters] zipfilename.2fz filelist
	
	cout << "Available zip/unzip parameters: " << endl;
	cout <<	"  -r   recurse into directories     -j   junk (don't record) directory names"		<< endl <<
			"  -0   store only                   -l   convert LF to CR LF (-ll CR LF to LF)"	<< endl <<
			"  -1   compress faster              -9   compress better"							<< endl <<
			"  -q   quiet operation              -v   verbose operation/print version info"		<< endl <<
			"  -c   add one-line comments        -z   add zipfile comment"						<< endl;
}

//HELPER METHODS:
//authCode, mallocCopy, getZipFilename, isEncryption, isDecryption
//generates and returns a random 4-character numeric authentication code
string authCode() {
	//Create the random 2-factor authentication code
	srand (time(NULL));
	int rndm = rand() % 10000;
	string rStr = patch::to_string(rndm);
	while(rStr.size() < 4) {
		rStr.insert(0,"0");
	}
	//cout << "authCode: " << rStr << endl;
	return rStr;
}

//pass a char* (ie character array) by reference to modify it
//(useful for allocating space and assigning string values to command parameter array items)
void mallocCopy(char* &s1, string value) {
	s1 = (char*)malloc(value.length()+1);
	strcpy(s1, value.c_str());
}
//determines success of TextBelt text via JSON reply analysis of success item
bool isSuccess(char* jsonReply) {
	string success = "\"success\": true";
	if(strstr(jsonReply, success.c_str())) return true;
	else return false;
}

//parses the provided argument list for the name of the created zip file
//useful for texting the name of the file which an authCode unlocks
string getZipFilename(int argc, char** argv) {
	if(argc < 4) {
		return 0;
	}
	int i;
	for(i = 3;i<argc;i++) {
		if(argv[i][0] != '-') break;
	}
	return string(argv[i]);
}

//Determine whether to follow:
//encryption path (gen auth, gen zip, send text, (revert))
//OR
//decryption path (get auth, unzip file)
bool isEncryption(int argc, char** argv) {
	if(argc < 2) return false;
	return (strcmp(argv[1], "-e") == 0);
}
bool isDecryption(int argc, char** argv) {//note: not necessarily !isEncryption
	if(argc < 2) return false;
	return (strcmp(argv[1], "-d") == 0);
}

//parses arguments, generating appropriate (un)zip command
//generates authCode to be used for encryption, if necessary
//returns array of character arrays to be exec()d
char** parseArgs(int argc, char** argv) {
	if(argc < 4) {
		return 0;
	}

	bool isEncr = isEncryption(argc, argv);
	bool isDecr = isDecryption(argc, argv);
	if(!isEncr && !isDecr) {
		return 0;
	}
	
	int cmdSize = argc+1;//1 extra for the NULL terminator
	char** zipCmd = new char*[cmdSize];
	zipCmd[cmdSize-1] = NULL;
	char* cmdType = (char*)malloc(6);
	if(isEncr) {
		strcpy(cmdType, ZIP.c_str());
	}
	else if(isDecr) {
		strcpy(cmdType, UNZIP.c_str());
	}

	zipCmd[0] = cmdType;//zip or unzip
	mallocCopy(zipCmd[1], "-P");//password parameter identifier
	
	string pwd;
	if(isEncr) {
		theAuthCode = authCode();
		pwd = theAuthCode + ":" + patch::to_string(argv[2]);
	}
	else if(isDecr) {
		string theAuthCode;
		cout << "Enter 2Factor Authentication Code: " << endl << "  ";
		cin >> theAuthCode;
		pwd = theAuthCode + ":" + patch::to_string(argv[2]);
	}
	if(pwd.empty()) return 0;
	mallocCopy(zipCmd[2], pwd);//authCode:password

	for(int i = 3; i<argc; i++) {
		zipCmd[i] = argv[i];//addition parameters (includes "... zipName [list of files]")
	}
	
	return zipCmd;
}

// 1.  parses arguments for a proper (un)zip command, generating (or retrieving) an authCode
// 2.  (un)zips file
//[3.] if zip successful, generates text
//[4.] if text fails, reverts zip]
int main(int argc, char** argv) {
	char** zipCmd = parseArgs(argc, argv);
	if(zipCmd == 0) {
		helpMenu();
		return 0;
	}
	
	bool noErrors = generateZip(zipCmd);
	if(noErrors && isEncryption(argc, argv)) {
		string phoneNum;
		cout << "Enter recipient's (10-digit) phone number (form: xxxxxxxxxx): " << endl;
		cin >> phoneNum;
		
		noErrors = generateText(theAuthCode, phoneNum, getZipFilename(argc, argv));
		if(!noErrors) {
			undoGenerateZip(getZipFilename(argc, argv));
			cout << "Error sending authorization code to recipient" << endl;
		}
	}

	return 0;
}

//generates zip file
//return true if successful
bool generateZip(char** zipCmd) {
	//cout << "Original PID: " << getpid() << endl;
	int n, fd[2], status; char buf[100];
	pipe(fd);//generate pipe for communicating between main and child/text process
	
	pid_t pid = fork();//create child process
	switch(pid) {
		case -1: {//ERROR
			cerr << "  ERROR: (un)zip fork() failed" << endl;
			exit(1);
		}
		case 0: {//CHILD
			close(fd[0]);//close read end of pipe
			
			//Redirect stdout-stderr to parent to test for success
			dup2(fd[1], STDOUT_FILENO);
			dup2(fd[1], STDERR_FILENO);
			
			execvp(zipCmd[0], zipCmd);//execute program
			cerr << "  ERROR: (un)compressing zip" << endl;//exec doesn't return unless there's an error
			exit(1);
		}
		default: {//PARENT
			close(fd[1]);
			//cout << "(un)zip process created; PID: " << pid << endl;

			while(true) {
				n = read(fd[0], buf, 100);//Read from pipe
				if(n <= 0) break;
				write(STDOUT_FILENO,buf,n);//Write to standard output
			}
			
			do {
				waitpid(pid, &status, 0);//wait for process to complete
			} while(!WIFEXITED(status) && !WIFSIGNALED(status));
			
			//cout << "(un)zip process exit status: " << WEXITSTATUS(status) << endl;
			break;
		}
	}
	close(fd[0]);
	close(fd[1]);
	return status == 0;
}

//generates a TextBelt text message for the authCode to the phoneNum
//returns true if text successful
//returns false if text unsuccessful
bool generateText(string authCode, string phoneNum, string filename) {
	string number = "number=" + phoneNum;
	string message = "message=2Factor Auth Code for " + filename + ": " + authCode;
	
	char** textCmd = new char*[10];
	mallocCopy(textCmd[0], "curl");
	mallocCopy(textCmd[1], "--silent");
	mallocCopy(textCmd[2], "-X");
	mallocCopy(textCmd[3], "POST");
	mallocCopy(textCmd[4], TEXTBELT_URL);
	mallocCopy(textCmd[5], "-d");
	mallocCopy(textCmd[6], number);
	mallocCopy(textCmd[7], "-d");
	mallocCopy(textCmd[8], message);
	textCmd[9] = NULL;
	
	int n, fd[2]; char buf[100];
	pipe(fd);//generate pipe for communicating between main and child/text process
	pid_t pid = fork();//create child process
	switch(pid) {
		case -1: {//ERROR
			cerr << "  ERROR: text fork() failed" << endl;
			exit(1);
		}
		case 0: {//CHILD
			close(fd[0]);//close read end of pipe
			
			//Redirect stdout-stderr to parent to test for success
			dup2(fd[1], STDOUT_FILENO);
			dup2(fd[1], STDERR_FILENO);
			
			execvp(textCmd[0], textCmd);//execute program
			cerr << "  ERROR: text generation failed!" << endl;//exec doesn't return unless there's an error
			
			exit(1);
		}
		default: {//PARENT
			close(fd[1]);//close write end of pipe
			//cout << "Text process created; PID: " << pid << endl;
			int status;
			
			dup2(fd[0], STDIN_FILENO);
			
			n = read(fd[0], buf, 100);//Read from pipe
			//write(STDOUT_FILENO,buf,n);//Write to standard output
			
			do {
				waitpid(pid, &status, 0);//wait for process to complete
			} while(!WIFEXITED(status) && !WIFSIGNALED(status));
			//cout << "\nText process exit status: " << WEXITSTATUS(status) << "\n";
			
			break;
		}
	}
	close(fd[0]);
	close(fd[1]);
	return isSuccess(buf);
}

//reverts creation of zip
void undoGenerateZip(string zipName) {
	char** undoCmd = new char*[3];
	mallocCopy(undoCmd[0], "rm");
	mallocCopy(undoCmd[1], zipName);
	undoCmd[2] = NULL;
	
	pid_t pid = fork();//create child process
	switch(pid) {
		case -1: {//ERROR
			cerr << "  ERROR: undo zip fork() failed" << endl;
			exit(1);
		}
		case 0: {//CHILD
			execvp(undoCmd[0], undoCmd);//execute program
			cerr << "  ERROR: undo zip failed!" << endl;//exec doesn't return unless there's an error
			
			exit(1);
		}
		default: {//PARENT
			//cout << "Undo zip process created; PID: " << pid << endl;
			int status;

			do {
				waitpid(pid, &status, 0);//wait for process to complete
			} while(!WIFEXITED(status) && !WIFSIGNALED(status));
			//cout << "Undo zip process exit status: " << WEXITSTATUS(status) << "\n";
			
			break;
		}
	}
}