#include "../include/suspiciousfile.h"
#include <string>

suspiciousfile::suspiciousfile(std::string p, std::string e, suspiciousfile::EXTENS t) {
	this->path = p;
	this->extension = e;
	this->type = t;
}
