#include <iostream>

#include "Client.h"
#include "Server.h"

int main()
{
	Server server{ "example_db.db3" };

	Client client{ server };

	client.run();

	return 0;
}