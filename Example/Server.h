#pragma once

#include <string>
#include <memory>

#include <SQLiteCpp/SQLiteCpp.h>

#include "ServerInterface.h"

class Server : public ServerInterface
{
public:
	static constexpr int db_verion{ 1 };

	Server(const std::string& db_name);

	bool userExists(const std::string& name) override;
	bool createUser(const std::string& name, const std::string& passw) override;
	LoginResult loginUser(const std::string& name, const std::string& passw) override;
	bool performWebauthn(const webauthn::GetAssertionResult& result) override;

	bool addWebauthn(const std::string& name, const webauthn::MakeCredentialResult& result, 
		const webauthn::RelyingParty& rp, const webauthn::UserData& user) override;

protected:
	void openDB();
	void initDB();

public:
	std::string db_name;
	std::unique_ptr<SQLite::Database> db;

	std::vector<std::byte> last_auth_data{};
	std::vector<std::byte> last_user_id{};
	std::vector<std::byte> last_RP_id{};
	std::vector<std::byte> last_challenge{};;
};

