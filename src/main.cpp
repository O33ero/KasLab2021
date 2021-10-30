// Жеребцов К. Лабаратория Касперсокого 2021
#include <iostream>
#include <set>
#include <fstream>

#include <filesystem>	// Для прокрутки файлов в директории
#include <regex>		// Для поиска расширения файла

#include "include/suspiciousfile.h"

using namespace std;

int main(int argc, char* argv[]) {
	if (argc != 2) {
		cout << "Too few arguments" << endl;
	}

	unsigned int TOTAL = 0;
	unsigned int JS = 0;
	unsigned int CMD = 0;
	unsigned int EXE = 0;
	unsigned int ERR = 0;

	set<string> JS_extensions = { ".js" };
	set<string> CMD_extensions = { ".cmd", ".bat" };
	set<string> EXE_extensions = { ".exe", ".dll" };

	regex pattern("\.[a-z]*$");

	string JS_suspicious = "<script>evil_script()</script>";				// Для .js
	string CMD_suspicious = "rd /s /q \"c:\\windows";						// Для .cmd/.bat
	string EXE_suspicious[] = { "CreateRemoteThread", "CreateProcess" };	// Для .exe/.dll



	string path = "f://AAA//";

	filesystem::directory_iterator fs_iterator;
	try
	{
		filesystem::directory_iterator fs_iterator = filesystem::directory_iterator(path);
	}
	catch (const exception& ex)
	{
		cout << "Cannot find directory: " + path;
		return 0;
	}
	
	for (const auto& file : filesystem::directory_iterator(path)) {

		if (file.is_directory()) {
			continue;
		}

		string filename = file.path().string();								
		auto iter = sregex_iterator(filename.begin(), filename.end(), pattern); // Ищем расширение файла через регексу
		string filename_extension = (*iter).str();

		
		suspiciousfile* file;
		
		TOTAL += 1;
		bool is_suspect = false;

		if (is_suspect == false && JS_extensions.contains(filename_extension)) {
			file = new suspiciousfile(filename, filename_extension, suspiciousfile::JS);
			is_suspect = true;
			JS += 1;
		}
		if (is_suspect == false && CMD_extensions.contains(filename_extension)) {
			file = new suspiciousfile(filename, filename_extension, suspiciousfile::CMD);
			is_suspect = true;
			CMD += 1;
		}
		if (is_suspect == false && EXE_extensions.contains(filename_extension)) {
			file = new suspiciousfile(filename, filename_extension, suspiciousfile::EXE);
			is_suspect = true;
			EXE += 1;
		}

		if (is_suspect == false) continue;
		
		
		
		
		cout << filename << endl;
		try
		{
			ifstream input(filename, ios::binary);
			string line;

			while (getline(input, line)) {
				cout << line << endl;
			}
			
		}
		catch (const std::exception&)
		{
			ERR += 1;
			continue;
		}

	}

	cout << "TOTAL = " << TOTAL << endl;
	cout << "JS    = " << JS << endl;
	cout << "CMD   = " << CMD << endl;
	cout << "EXE   = " << EXE << endl;
	cout << "ERR   = " << ERR << endl;

	return 0;
}