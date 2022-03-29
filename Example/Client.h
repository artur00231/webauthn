#pragma once

#include <iostream>
#include <optional>

#include "ServerInterface.h"

class Client
{
public:
	Client(ServerInterface& server) : server{ server } {}

	void run();

protected:
	void printMenu();
	int getUserChose();
	
	template<typename T>
	T standardUserInput();

	void checkUser();
	void addUser();
	void loginUser();

private:
	ServerInterface& server;
	std::ostream& out{ std::cout };
	std::istream& in{ std::cin };
};

template<typename T>
inline T Client::standardUserInput()
{
	T value{};

	in >> value;

	return value;
}
