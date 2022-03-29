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
	bool loginUser(const std::string& name, const std::string& passw) override;

protected:
	void openDB();
	void initDB();

public:
	std::string db_name;
	std::unique_ptr<SQLite::Database> db;
};

