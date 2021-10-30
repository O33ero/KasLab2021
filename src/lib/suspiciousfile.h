#pragma once
#include <string>
class suspiciousfile
{

public:
	enum EXTENS {
		JS,
		CMD,
		EXE
	};

	std::string path;
	std::string extension;
	enum EXTENS type;


	suspiciousfile(std::string p, std::string e, enum EXTENS t) {}

};

