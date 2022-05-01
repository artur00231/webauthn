#include "Client.h"

#include <iomanip>

#include <WebAuthn.h>
#include <WebAuthnWinHello.h>
#include <Webauthnlibfido2.h>

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

		case 4:
			addWebauthn();
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
	out << std::setw(2) << 4 << "| Add webauthn\n";
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
	auto result = server.loginUser(user, passw);

	if (result.result == ServerInterface::LOGIN_RESULT::SUCCESS)
	{
		out << "Login successfull\n";
		return;
	}
	else if (result.result == ServerInterface::LOGIN_RESULT::WRONG_DATA)
	{
		out << "Wrong login information\n";
		return;
	}
	else if (result.result == ServerInterface::LOGIN_RESULT::SERV_ERR)
	{
		out << "Server error\n";
		return;
	}

	//Webauthn required
	//webauthn::impl::WebAuthnWinHello impl{};
	webauthn::impl::Webauthnlibfido2 impl{};
	webauthn::WebAuthn webauthn{ RP, impl };

	out << "FIDO2 passw: ";
	auto fido_passw = standardUserInput<std::string>();
	auto webauthn_result = webauthn.getAssertion({ *result.credential_id }, *result.challenge, fido_passw);
	fido_passw = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

	if (!webauthn_result)
	{
		out << "System error\n";
		return;
	}

	auto success = server.performWebauthn(*webauthn_result);

	if (success)
	{
		out << "Login successfull\n";
	}
	else
	{
		out << "Wrong login information\n";
	}
}

void Client::addWebauthn()
{
	out << "User name: ";
	auto user = standardUserInput<std::string>();
	out << "User passw: ";
	auto passw = standardUserInput<std::string>();

	out << "Login as " << user << "\n";
	auto login = server.loginUser(user, passw);

	if (login.result == ServerInterface::LOGIN_RESULT::WRONG_DATA)
	{
		out << "Cannot login\n";
		return;
	}

	if (login.result == ServerInterface::LOGIN_RESULT::AUTH_REQ)
	{
		out << "Webauthn already active\n";
		return;
	}

	//Webauthn required
	//webauthn::impl::WebAuthnWinHello impl{};
	webauthn::impl::Webauthnlibfido2 impl{};
	webauthn::WebAuthn webauthn{ RP, impl };

	webauthn::UserData user_data{};
	user_data.display_name = user;
	user_data.name = user;

	if (!webauthn::UserData::generateRandomID(32).and_then(
		[&user_data](auto&& x) {
			user_data.ID = std::move(x);
			return std::make_optional(true);
		})) 
	{
		out << "System error\n";
		return;
	}

	out << "FIDO2 passw: ";
	auto fido_passw = standardUserInput<std::string>();

	std::vector<std::byte> challage(32, std::byte(0));
	auto result = webauthn.makeCredential(user_data, challage, fido_passw);
	fido_passw = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

	if (!result)
	{
		out << "System error\n";
		return;
	}

	auto success = server.addWebauthn(user, *result, RP, user_data);

	if (success)
	{
		out << "Added\n";
	}
	else
	{
		out << "Server error\n";
	}
}
