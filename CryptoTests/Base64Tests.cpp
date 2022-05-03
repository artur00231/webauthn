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

		static const auto base64_1 = "cXdlcnR5"s;
		static const auto bin_1 = "qwerty"s;

		static const auto base64_2 = "ZmJlZmloYWJmaWhiYQ=="s;
		static const auto bin_2 = "fbefihabfihba"s;

		static const auto base64_3 = "YXNkZmdoZmRzZnNkZXI="s;
		static const auto bin_3 = "asdfghfdsfsder"s;

		static const auto base64Url_4 = "ZHNhZHNhZA"s;
		static const auto bin_4 = "dsadsad"s;

		static const auto base64Url_5 = "ZHNhZHNhZGc"s;
		static const auto bin_5 = "dsadsadg"s;

		static const auto base64Url_6 = "HDvbWT_dyd-dw_wd_--ddw"s;
		static const std::vector<unsigned char> bin_6{ 0x1c, 0x3b, 0xdb, 0x59, 0x3f, 0xdd, 0xc9, 0xdf, 0x9d, 0xc3, 0xfc, 0x1d, 0xff, 0xef, 0x9d, 0x77 };
	}

	TEST(Base64Tests, Decode1)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64<std::string>(helpers::text1);

		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ("abc"s, *decoded);
	}

	TEST(Base64Tests, Decode2)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64<std::string>(helpers::text3);

		EXPECT_FALSE(decoded.has_value());
	}

	TEST(Base64Tests, DecodeFix1)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Url<std::string>(helpers::text2);

		ASSERT_TRUE(decoded.has_value());

		EXPECT_EQ("hbdsudnbfhdkhngyhf"s, *decoded);
	}

	TEST(Base64Tests, DecodeFix2)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Url<std::string>(helpers::text3);

		ASSERT_TRUE(decoded.has_value());

		EXPECT_EQ("nojdfhydfgbfds"s, *decoded);
	}

	TEST(Base64Tests, EncodeDecode1)
	{
		auto decoded = crypto::base64::fromBase64<std::string>(helpers::base64_1);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_1, *decoded);

		auto base64_1 = helpers::base64_1;
		decoded = crypto::base64::fromBase64<std::string>(base64_1);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_1, *decoded);

		decoded = crypto::base64::fromBase64<std::string>(std::move(base64_1));
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_1, *decoded);

		auto encoded = crypto::base64::toBase64<std::string>(helpers::bin_1);
		EXPECT_EQ(helpers::base64_1, encoded);

		auto bin_1 = helpers::bin_1;
		encoded = crypto::base64::toBase64<std::string>(bin_1);
		EXPECT_EQ(helpers::base64_1, encoded);

		encoded = crypto::base64::toBase64<std::string>(std::move(bin_1));
		EXPECT_EQ(helpers::base64_1, encoded);
	}

	TEST(Base64Tests, EncodeDecode2)
	{
		auto decoded = crypto::base64::fromBase64<std::string>(helpers::base64_2);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_2, *decoded);

		auto encoded = crypto::base64::toBase64<std::string>(helpers::bin_2);
		EXPECT_EQ(helpers::base64_2, encoded);
	}

	TEST(Base64Tests, EncodeDecode3)
	{
		auto decoded = crypto::base64::fromBase64<std::string>(helpers::base64_3);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_3, *decoded);

		auto encoded = crypto::base64::toBase64<std::string>(helpers::bin_3);
		EXPECT_EQ(helpers::base64_3, encoded);
	}

	TEST(Base64Tests, EncodeDecode4)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Url<std::string>(helpers::base64Url_4);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_4, *decoded);

		auto encoded = crypto::base64::toBase64<std::string>(helpers::bin_4);
		auto expected_encoded = helpers::base64Url_4 + "=="s;
		EXPECT_EQ(expected_encoded, encoded);
	}

	TEST(Base64Tests, EncodeDecode5)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Url<std::string>(helpers::base64Url_5);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_5, *decoded);

		auto encoded = crypto::base64::toBase64<std::string>(helpers::bin_5);
		auto expected_encoded = helpers::base64Url_5 + "="s;
		EXPECT_EQ(expected_encoded, encoded);
	}

	TEST(Base64Tests, EncodeDecode6)
	{
		using namespace std::string_literals;

		auto decoded = crypto::base64::fromBase64Url<std::vector<unsigned char>>(helpers::base64Url_6);
		ASSERT_TRUE(decoded.has_value());
		EXPECT_EQ(helpers::bin_6, *decoded);

		auto encoded = crypto::base64::toBase64<std::string>(helpers::bin_6);
		auto expected_encoded = helpers::base64Url_6 + "=="s;
		std::ranges::for_each(expected_encoded, [](auto& x) {
			switch (x)
			{
			case '_':
				x = '/';
				break;
			case '-':
				x = '+';
				break;
			}
			});
		EXPECT_EQ(expected_encoded, encoded);
	}
}