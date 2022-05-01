#include "pch.h"

#include <Base64.h>

namespace webauthn::crypto
{
	namespace helpers
	{
		using namespace std::string_literals;

		static const auto text1 = "YWJj"s;
		static const auto text2 = "aGJkc3VkbmJmaGRraG5neWhm"s;
		static const auto text3 = "bm9qZGZoeWRmZ2JmZHM"s;
	}

	TEST(CryptoTests, Decode1)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64<std::string>(helpers::text1);

		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ("abc"s, *decoded);
	}

	TEST(CryptoTests, Decode2)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64<std::string>(helpers::text3);

		EXPECT_FALSE(decoded.has_value());
	}

	TEST(CryptoTests, DecodeFix1)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Fix<std::string>(helpers::text2);

		ASSERT_TRUE(decoded.has_value());

		EXPECT_EQ("hbdsudnbfhdkhngyhf"s, *decoded);
	}

	TEST(CryptoTests, DecodeFix2)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Fix<std::string>(helpers::text3);

		ASSERT_TRUE(decoded.has_value());

		EXPECT_EQ("nojdfhydfgbfds"s, *decoded);
	}
}