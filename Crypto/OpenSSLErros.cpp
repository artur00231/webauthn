#include "OpenSSLErros.h"

#include <openssl/err.h>

std::optional<std::string> webauthn::crypto::OpenSSLErros::getLastError()
{
	auto error = ERR_get_error();
	if (error == 0)
	{
		return {};
	}

	char error_text[200];
	ERR_error_string(error, error_text);
	return { error_text };
}
