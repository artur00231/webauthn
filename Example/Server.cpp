#include "Server.h"

#include <filesystem>
#include <algorithm>
#include <ranges>
#include <span>

#include <Hash.h>
#include <Random.h>
#include <PublicKey.h>

#include <AttestationObject.h>
#include <WebAuthnExceptions.h>

Server::Server(const std::string& db_name) : db_name{ db_name }
{
	openDB();
}

bool Server::userExists(const std::string& name)
{
	std::string query{ "SELECT COUNT(name) AS value FROM Users WHERE name = ?" };
	SQLite::Statement statement{ *db, query };

	statement.bind(1, name);
	statement.executeStep();

	return statement.getColumn("value").getInt64();
}

bool Server::createUser(const std::string& name, const std::string& passw)
{
	std::string query{ R"(INSERT INTO Users ( name, salt, passw ) VALUES ( ?, ?, ? ))" };
	SQLite::Statement statement{ *db, query };

	auto maybe_salt = webauthn::crypto::random::genRandom(16);
	if (!maybe_salt)
	{
		return false;
	}
	auto& salt = maybe_salt.value();

	auto passw_key = webauthn::crypto::hash::PBKDF2<>(passw, salt);

	statement.bind(1, name);
	statement.bind(2, salt.data(), static_cast<int>(salt.size()));
	statement.bind(3, passw_key.data(), static_cast<int>(passw_key.size()));

	try {
		auto changed = statement.exec();
	}
	catch ([[maybe_unused]] const SQLite::Exception& exception)
	{
		return false;
	}

	return true;
}

ServerInterface::LoginResult Server::loginUser(const std::string& name, const std::string& passw)
{
	std::string query{ R"(SELECT salt, passw FROM Users WHERE name = ?)" };
	SQLite::Statement statement{ *db, query };

	statement.bind(1, name);

	auto result = statement.tryExecuteStep();
	static constexpr int SQLITE_ROW = 100;

	if (result == SQLITE_ROW)
	{
		auto salt_ptr = statement.getColumn("salt").getBlob();
		auto salt_size = statement.getColumn("salt").getBytes();
		std::vector<std::byte> salt{};
		std::copy_n(reinterpret_cast<const std::byte*>(salt_ptr), salt_size, std::back_inserter(salt));

		auto passw_key_ptr = statement.getColumn("passw").getBlob();
		auto passw_key_size = statement.getColumn("passw").getBytes();
		std::vector<std::byte> passw_key{};
		std::copy_n(reinterpret_cast<const std::byte*>(passw_key_ptr), passw_key_size, std::back_inserter(passw_key));

		auto good_passw_key = webauthn::crypto::hash::PBKDF2<>(passw, salt);

		auto eq = std::ranges::equal(passw_key, good_passw_key);

		if (!eq)
		{
			return { ServerInterface::LOGIN_RESULT::WRONG_DATA, {} };
		}

		std::string query{ R"(SELECT auth_data, user_id, RP_ID FROM Users INNER JOIN webauthn ON user == name WHERE name == ?)" };
		SQLite::Statement statement{ *db, query };
		statement.bind(1, name);

		auto result = statement.tryExecuteStep();
		if (result == SQLITE_ROW)
		{
			last_auth_data.clear();
			std::span auth_data{ reinterpret_cast<const std::byte*>(statement.getColumn("auth_data").getBlob()), 
				static_cast<std::size_t>(statement.getColumn("auth_data").getBytes()) };
			std::copy(auth_data.begin(), auth_data.end(), std::back_inserter(last_auth_data));

			last_user_id.clear();
			std::span user_id{ reinterpret_cast<const std::byte*>(statement.getColumn("user_id").getBlob()),
				static_cast<std::size_t>(statement.getColumn("user_id").getBytes()) };
			std::copy(user_id.begin(), user_id.end(), std::back_inserter(last_user_id));

			last_RP_id.clear();
			std::span RP_ID{ reinterpret_cast<const std::byte*>(statement.getColumn("RP_ID").getBlob()),
				static_cast<std::size_t>(statement.getColumn("RP_ID").getBytes()) };
			std::copy(RP_ID.begin(), RP_ID.end(), std::back_inserter(last_RP_id));

			last_challenge.clear();
			auto random = webauthn::crypto::random::genRandom(32);
			if (!random)
			{
				return { ServerInterface::LOGIN_RESULT::SERV_ERR, {} };
			}
			last_challenge = *random;

			auto auth_data_obj = webauthn::AuthenticatorData::fromBin(last_auth_data);
			if (!auth_data_obj.attested_credential_data)
			{
				//Invalid AuthenticatorData, credential_id is required to perform getAssertion
				//TODO
				return { ServerInterface::LOGIN_RESULT::WRONG_DATA, {} };
			}

			return { ServerInterface::LOGIN_RESULT::AUTH_REQ, auth_data_obj.attested_credential_data->credential_id, last_challenge };
		}
		else //No webauthn
		{
			return { ServerInterface::LOGIN_RESULT::SUCCESS, {} };
		}
	}

	return { ServerInterface::LOGIN_RESULT::WRONG_DATA, {} };
}

bool Server::performWebauthn(const webauthn::GetAssertionResult& result)
{
	bool success{ false };

	try {
		auto auth_data = webauthn::AuthenticatorData::fromBin(last_auth_data);

		std::vector<std::byte> to_verify{};
		std::copy(result.authenticator_data.begin(), result.authenticator_data.end(), std::back_inserter(to_verify));

		auto challage_hash = webauthn::crypto::hash::SHA256(last_challenge);
		std::copy(challage_hash.begin(), challage_hash.end(), std::back_inserter(to_verify));

		auto verify_result = auth_data.attested_credential_data->key->public_key->verify(to_verify, result.signature);

		if (verify_result && *verify_result)
		{
			auto result_auth_data = webauthn::AuthenticatorData::fromBin(result.authenticator_data);

			//Compare PR_ID hash
			auto rp_id_eq = std::ranges::equal(result_auth_data.RP_ID_hash, auth_data.RP_ID_hash);

			if (rp_id_eq)
			{
				success = true;
			}
		}
	}
	catch ([[maybe_unused]] const webauthn::exceptions::WebAuthnExceptions& exc)
	{
		success = false;
	}

	last_auth_data.clear();
	last_RP_id.clear();
	last_user_id.clear();
	last_challenge.clear();

	return success;
}

bool Server::addWebauthn(const std::string& name, const webauthn::MakeCredentialResult& result, 
	const webauthn::RelyingParty& rp, const webauthn::UserData& user)
{
	try {
		auto attestation_o = webauthn::AttestationObject::fromCbor(result.attestation_object);

		if (webauthn::crypto::hash::SHA256(rp.ID) != attestation_o.authenticator_data.RP_ID_hash)
		{
			return false;
		}
		auto auth_data = attestation_o.authenticator_data.toBin();

		std::string query{ R"(INSERT INTO webauthn ( user, auth_data, user_id, RP_ID ) VALUES ( ?, ?, ?, ? ))" };
		SQLite::Statement statement{ *db, query };

		statement.bind(1, name);
		statement.bind(2, auth_data.data(), static_cast<int>(auth_data.size()));
		statement.bind(3, user.ID.data(), static_cast<int>(user.ID.size()));
		statement.bind(4, rp.ID.data(), static_cast<int>(rp.ID.size()));

		try {
			auto changed = statement.exec();
		}
		catch ([[maybe_unused]] const SQLite::Exception& exception)
		{
			return false;
		}
	}
	catch ([[maybe_unused]] const webauthn::exceptions::WebAuthnExceptions& exc)
	{
		return false;
	}

	return true;
}

void Server::openDB()
{
	try
	{
		//Open existing
		SQLite::Database data_base{ db_name, SQLite::OPEN_READWRITE };
		db = std::make_unique<SQLite::Database>(std::move(data_base));

		//Check version
		long long verion{};
		{
			std::string query{ "SELECT * FROM Version" };
			SQLite::Statement statement{ *db, query };
			statement.executeStep();

			verion = statement.getColumn("version").getInt64();
		}

		if (verion != db_verion)
		{
			db.reset();
			std::filesystem::remove(db_name);

			throw SQLite::Exception{ "Invalid db version", 0 };
		}
	}
	catch ([[maybe_unused]] const SQLite::Exception& exception)
	{
		//Create new
		SQLite::Database data_base{ db_name, SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE };
		db = std::make_unique<SQLite::Database>(std::move(data_base));

		initDB();
	}
}

void Server::initDB()
{
	std::string query{ "CREATE TABLE Users (name TEXT PRIMARY KEY UNIQUE, salt BLOB NOT NULL, passw BLOB NOT NULL);" };

	SQLite::Statement statement{ *db, query };
	auto result = statement.exec();
	statement.~Statement();

	query = { "CREATE TABLE webauthn (user TEXT UNIQUE, auth_data BLOB, user_id BLOB NOT NULL, RP_ID BLOB NOT NULL);" };
	new(&statement) SQLite::Statement{ *db, query };
	result = statement.exec();
	statement.~Statement();

	query = { "CREATE TABLE Version (version INTEGER);" };
	new(&statement) SQLite::Statement{ *db, query };
	result = statement.exec();
	statement.~Statement();

	query = { "INSERT INTO Version VALUES ( ? )" };
	new(&statement) SQLite::Statement{ *db, query };
	statement.bind(1, db_verion);
	result = statement.exec();
}
