#include "lib/suspiciousfile.h"
#include <string>

suspiciousfile::suspiciousfile(std::string p, std::string e, enum EXTENS t) {
	this->path = p;
	this->extension = e;
	this->type = t;
}
