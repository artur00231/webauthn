#include "Client.h"

#include <iomanip>

void Client::run()
{
	bool done{ false };
	while (!done)
	{
		printMenu();
		auto selected = getUserChose();

		switch (selected)
		{
		case 1:
			checkUser();
			break;

		case 2:
			addUser();
			break;

		case 3:
			loginUser();
			break;

		case 10:
			done = true;
			break;

		default:
			break;
		}
	}
}

void Client::printMenu()
{
	out << "Example Client\n";
	out << std::setw(2) << 1 << "| Check user\n";
	out << std::setw(2) << 2 << "| Crate user\n";
	out << std::setw(2) << 3 << "| Login user\n";
	out << std::setw(2) << 10 << "| End\n";
	out << "\t>";
}

int Client::getUserChose()
{
	int value{};

	in >> value;

	return value;
}

void Client::checkUser()
{
	out << "User name: ";
	auto user = standardUserInput<std::string>();

	out << "Checking " << user << "\n";
	out << std::boolalpha << server.userExists(user) << "\n";
}

void Client::addUser()
{
	out << "User name: ";
	auto user = standardUserInput<std::string>();
	out << "User passw: ";
	auto passw = standardUserInput<std::string>();

	out << "Adding " << user << "\n";
	out << std::boolalpha << server.createUser(user, passw) << "\n";
}

void Client::loginUser()
{
	out << "User name: ";
	auto user = standardUserInput<std::string>();
	out << "User passw: ";
	auto passw = standardUserInput<std::string>();

	out << "Login as " << user << "\n";
	out << std::boolalpha << server.loginUser(user, passw) << "\n";
}
