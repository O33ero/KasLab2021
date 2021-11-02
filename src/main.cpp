#include <iostream>
#include <set>
#include <fstream>

#include <filesystem>   // For finding files in dir			(C++17)
#include <regex>        // For detecting extension of files (C++11)
#include <chrono>       // For time measuring				(C++11)


using namespace std;

// Types of suspicious files
enum EXTENS {
	NONE,
	JS,
	CMD,
	EXE
};

static unsigned int TOTAL_count = 0;
static unsigned int JS_count = 0;
static unsigned int CMD_count = 0;
static unsigned int EXE_count = 0;
static unsigned int ERR_count = 0;

set<string> JS_extensions = { ".js" };
set<string> CMD_extensions = { ".cmd", ".bat" };
set<string> EXE_extensions = { ".exe", ".dll" };

regex pattern("\.[a-z]*$");

string JS_suspicious = "<script>evil_script()</script>";                // For .js
string CMD_suspicious = "rd /s /q \"c:\\windows\"";                     // For .cmd/.bat
string EXE_suspicious[] = { "CreateRemoteThread", "CreateProcess" };    // For .exe/.dll


// Check string for matching with patterns
bool check_String(string* str, vector<string*> patterns) {
	for (auto now : patterns) {
		if (str->find(*now) != string::npos) {
			return true;
		}
	}
	return false;
}

// Handling suspicios file
void processing_File(const filesystem::directory_entry& file) {
	TOTAL_count += 1;




	string file_name = file.path().string(); // *NAME								
	auto iter = sregex_iterator(file_name.begin(), file_name.end(), pattern); // Finding extension by regex 
	string file_extension = (*iter).str();   // *EXTENSIONS
	enum EXTENS file_extens = NONE;          // *TYPE


	if (file_extens == NONE && JS_extensions.contains(file_extension)) {
		file_extens = JS;
	}
	if (file_extens == NONE && CMD_extensions.contains(file_extension)) {
		file_extens = CMD;
	}
	if (file_extens == NONE && EXE_extensions.contains(file_extension)) {
		file_extens = EXE;
	}
	if (file_extens == NONE) return; // File is non-suspicios



	ifstream input(file_name, ios::binary);

	try // File is probably suspicios
	{
		if (!input.is_open()) {
			input.close();
			throw runtime_error("File cannot be open");
		}

		vector<string*> suspicious_strings;

		// Preparing vector with suspicious strings
		switch (file_extens)
		{
		case JS:
			suspicious_strings.push_back(&JS_suspicious);
			break;
		case CMD:
			suspicious_strings.push_back(&CMD_suspicious);
			break;
		case EXE:
			suspicious_strings.push_back(&EXE_suspicious[0]);
			suspicious_strings.push_back(&EXE_suspicious[1]);
			break;
		}

		string line;

		// Searching suspicuous strings
		while (getline(input, line, (char)0)) {
			bool is_supicious = check_String(&line, suspicious_strings);
			if (is_supicious) {
				switch (file_extens) {
				case JS:
					JS_count += 1;
					break;
				case CMD:
					CMD_count += 1;
					break;
				case EXE:
					EXE_count += 1;
					break;
				}
			}

			if (is_supicious) break;
		}

		input.close();

	}
	catch (const std::exception&)
	{
		input.close();
		ERR_count += 1;
	}
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		if (argc < 2) cout << "Too few arguments" << endl;
		else          cout << "Too many arguments" << endl;
		cout << "Expected: scan_util <PATH>" << endl;
		return 0;
	}

	auto start_time = chrono::steady_clock::now(); // Time measuring

	string path = argv[1];

	filesystem::directory_iterator fs_iterator;
	try
	{
		filesystem::directory_iterator fs_iterator = filesystem::directory_iterator(path); // If cannot find dir, will be thrown exception
	}
	catch (const exception& ex)
	{
		cout << "Cannot find directory: " + path << endl;
		return 0;
	}
	
	for (const filesystem::directory_entry& file : filesystem::directory_iterator(path)) {

		if (file.is_directory()) { // Skipping dirs
			continue;
		}

		processing_File(file);
	}

	auto end_time = chrono::steady_clock::now();

	chrono::duration<double> spend_time = end_time - start_time; // Full-time in seconds (double)
	int hours = static_cast<int>(spend_time.count()) / 3600;	
	int minutes = (static_cast<int>(spend_time.count()) - 3600 * hours) / 60;
	double seconds = spend_time.count() - (3600 * hours) - (60 * minutes);

	// Result of program
	cout << "\n\n====== Scan result ======\n\n";
	cout << "TOTAL = " << TOTAL_count << endl << endl;
	cout << "JS    = " << JS_count << endl << endl;
	cout << "CMD   = " << CMD_count << endl << endl;
	cout << "EXE   = " << EXE_count << endl << endl;
	cout << "ERR   = " << ERR_count << endl << endl;
	printf("Time spend: %02d:%02d:%.3f \n\n", hours, minutes, seconds);
	cout << "=========================\n";

	return 0;
}