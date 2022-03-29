#pragma once

#include <string>
#include <vector>

class ServerInterface
{
public:
	virtual bool userExists(const std::string& name) = 0;
	virtual bool createUser(const std::string& name, const std::string& passw) = 0;
	virtual bool loginUser(const std::string& name, const std::string& passw) = 0;
};