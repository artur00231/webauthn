#pragma once

#include <stdexcept>
#include <string>

namespace webauthn
{
	namespace exceptions
	{
		class WebAuthnExceptions : public ::std::runtime_error
		{
		public:
			WebAuthnExceptions(const ::std::string& message) : ::std::runtime_error{ message } {}
			WebAuthnExceptions(::std::string&& message) : ::std::runtime_error{ std::move(message) } {}
		};

		class FormatException : public WebAuthnExceptions
		{
		public:
			FormatException(const ::std::string& message) : WebAuthnExceptions{ message } {}
			FormatException(::std::string&& message) : WebAuthnExceptions{ std::move(message) } {}
		};

		class DataException : public WebAuthnExceptions
		{
		public:
			DataException(const ::std::string& message) : WebAuthnExceptions{ message } {}
			DataException(::std::string&& message) : WebAuthnExceptions{ std::move(message) } {}
		};
	}
}