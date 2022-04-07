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
	void addWebauthn();

private:
	ServerInterface& server;
	std::ostream& out{ std::cout };
	std::istream& in{ std::cin };

	webauthn::RelyingParty RP{ .ID = "example_RP", .name = "The example inc" };
};

template<typename T>
inline T Client::standardUserInput()
{
	T value{};

	in >> value;

	return value;
}
