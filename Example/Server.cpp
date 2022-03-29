#include "Server.h"

#include <filesystem>
#include <algorithm>
#include <ranges>

#include "../Crypto/Hash.h"
#include "../Crypto/Random.h"

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

bool Server::loginUser(const std::string& name, const std::string& passw)
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

		return std::ranges::equal(passw_key, good_passw_key);
	}

	return false;
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

	query = { "CREATE TABLE Version (version INTEGER);" };
	new(&statement) SQLite::Statement{ *db, query };
	result = statement.exec();

	query = { "INSERT INTO Version VALUES ( ? )" };
	new(&statement) SQLite::Statement{ *db, query };
	statement.bind(1, db_verion);
	result = statement.exec();
}
