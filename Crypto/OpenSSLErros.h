#pragma once

#include <string>
#include <optional>

namespace webauthn::crypto
{
	namespace OpenSSLErros
	{
		template<typename OS>
		concept OutputStream = requires(OS os)
		{
			{ os << std::declval<std::string>() } -> std::convertible_to<OS&>;
		};

		std::optional<std::string> getLastError();

		template<OutputStream OS>
		void printLastError(OS& os)
		{
			using namespace std::string_literals;
			auto error = getLastError();
			if (error.has_value())
			{
				os << error.value() << "\n"s;
			}
		}

		template<OutputStream OS>
		void printAllErrors(OS& os)
		{
			using namespace std::string_literals;
			auto error = getLastError();
			while (error.has_value())
			{
				os << error.value() << "\n"s;
				error = getLastError();
			}
		}

	};
}

