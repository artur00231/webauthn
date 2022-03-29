#pragma once

#include <stdexcept>

namespace webauthn::crypto
{
	class CryptoException : public ::std::runtime_error
	{
	public:
		CryptoException(const ::std::string& message) : ::std::runtime_error{ message } {}
		CryptoException(::std::string&& message) : ::std::runtime_error{ std::move(message) } {}
	};

	class OpenSSLException : public CryptoException
	{
	public:
		OpenSSLException(const ::std::string& message) : CryptoException{ message } {}
		OpenSSLException(::std::string&& message) : CryptoException{ std::move(message) } {}
	};
}