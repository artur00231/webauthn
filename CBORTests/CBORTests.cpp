#include "pch.h"

#include <cstddef>
#include <vector>
#include <set>
#include <string_view>

#include "../CBORLib/CBORLib.h"

namespace webauthn::CBOR
{
	namespace helpers
	{
		std::vector<std::byte> hexToBin(std::string_view hex)
		{
			std::vector<std::byte> data{};
			auto fromHex = [](char x) {
				if (x >= '0' && x <= '9')
					return (x - '0');
				if (x >= 'A' && x <= 'F')
					return (x - 'A' + 10);
				if (x >= 'a' && x <= 'f')
					return (x - 'a' + 10);

				throw std::runtime_error{ R"("fromHex" Invalid character)" };
			};

			for (std::size_t i = 0; i < hex.size(); i += 2)
			{
				std::uint8_t value = (fromHex(hex[i]) << 4) | fromHex(hex[i + 1]);
				data.push_back(static_cast<std::byte>(value));
			}

			return data;
		}

		//[1, 2, 3, 4, 5, -1, -10, -20, 10]
		static auto ex_CBOR_int1 = hexToBin("8901020304052029330A");

		/*
		{
			0:		[23, -1, -24],
			24:		[255 , -25, -256],
			256:	[65535, -257, -65536],
			65536:	[4294967295, -65537, -4294967296]
		}
		*/
		static auto ex_CBOR_int2 = hexToBin("A4008317203718188318FF381838FF1901008319FFFF39010039FFFF1A00010000831AFFFFFFFF3A000100003AFFFFFFFF");
	
		//["qwertyuiop", "1qaz5tgb9ol."]
		static auto ex_CBOR_string1 = hexToBin("826A71776572747975696F706C3171617A35746762396F6C2E");

		/*
		{
			0:		[23, -1, -24],
			24:		[255 , -25, -256],
			256:	[65535, -257, -65536],
			65536:	[4294967295, -65537, -4294967296]
		}
		*/
		static auto ex_CBOR_map_array1 = hexToBin("A4008317203718188318FF381838FF1901008319FFFF39010039FFFF1A00010000831AFFFFFFFF3A000100003AFFFFFFFF");

		static auto indefinite_map1 = hexToBin("BF0102FF");
		static auto indefinite_map2 = hexToBin("BF0102");
		static auto indefinite_array1 = hexToBin("9F01FF");
		static auto indefinite_array2 = hexToBin("9F01");

		static auto bin_array = hexToBin("4500010203FF");
		static auto bin_array_raw = std::vector<std::byte>{ std::byte{ 0x00 }, std::byte{ 0x01 }, std::byte{ 0x02 }, std::byte{ 0x03 }, std::byte{ 0xFF } };

	}

	TEST(CBOR_TEST, CBOR_Int1)
	{
		auto [cbor, result] = CBORHandle::fromBin(helpers::ex_CBOR_int1);

		EXPECT_TRUE(cbor);

		EXPECT_TRUE(cbor_isa_array(cbor));
		EXPECT_TRUE(cbor_array_is_definite(cbor));
		EXPECT_EQ(cbor_array_size(cbor), 9);

		auto elem = cbor_array_get(cbor, 0);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), 1);

		elem = cbor_array_get(cbor, 1);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), 2);

		elem = cbor_array_get(cbor, 2);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), 3);

		elem = cbor_array_get(cbor, 3);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), 4);

		elem = cbor_array_get(cbor, 4);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), 5);

		elem = cbor_array_get(cbor, 5);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), -1);

		elem = cbor_array_get(cbor, 6);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), -10);

		elem = cbor_array_get(cbor, 7);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), -20);

		elem = cbor_array_get(cbor, 8);
		EXPECT_TRUE(cbor_is_int(elem));
		ASSERT_TRUE(getIntegral<int>(elem));
		EXPECT_EQ(getIntegral<int>(elem).value(), 10);
	}

	TEST(CBOR_TEST, CBOR_Int2)
	{
		auto [cbor, result] = CBORHandle::fromBin(helpers::ex_CBOR_int2);

		EXPECT_TRUE(cbor);

		EXPECT_TRUE(cbor_isa_map(cbor));
		EXPECT_TRUE(cbor_map_is_definite(cbor));
		EXPECT_EQ(cbor_map_size(cbor), 4);

		auto begin = cbor_map_handle(cbor);
		auto end = cbor_map_handle(cbor) + 4;
		for (auto map_elem_it = begin; map_elem_it != end; map_elem_it++)
		{
			auto key = getIntegral<std::int64_t>(map_elem_it->key);
			ASSERT_TRUE(key);

			switch (key.value())
			{
			case 0:
			{
				EXPECT_TRUE(getIntegral<std::uint8_t>(map_elem_it->key));

				ASSERT_TRUE(cbor_isa_array(map_elem_it->value));
				ASSERT_TRUE(cbor_array_is_definite(map_elem_it->value));
				ASSERT_EQ(cbor_array_size(map_elem_it->value), 3);

				auto elem = cbor_array_get(map_elem_it->value, 0);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::uint8_t>(elem));
				EXPECT_EQ(getIntegral<std::uint8_t>(elem).value(), 23);

				elem = cbor_array_get(map_elem_it->value, 1);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int8_t>(elem));
				EXPECT_EQ(getIntegral<std::int8_t>(elem).value(), -1);

				ASSERT_FALSE(getIntegral<std::uint8_t>(elem));

				elem = cbor_array_get(map_elem_it->value, 2);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int8_t>(elem));
				EXPECT_EQ(getIntegral<std::int8_t>(elem).value(), -24);

				ASSERT_FALSE(getIntegral<std::uint8_t>(elem));
			}
				break;
			case 25:
			{
				EXPECT_TRUE(getIntegral<std::uint8_t>(map_elem_it->key));

				ASSERT_TRUE(cbor_isa_array(map_elem_it->value));
				ASSERT_TRUE(cbor_array_is_definite(map_elem_it->value));
				ASSERT_EQ(cbor_array_size(map_elem_it->value), 3);

				auto elem = cbor_array_get(map_elem_it->value, 0);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::uint8_t>(elem));
				EXPECT_EQ(getIntegral<std::uint8_t>(elem).value(), 255);

				elem = cbor_array_get(map_elem_it->value, 1);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int8_t>(elem));
				EXPECT_EQ(getIntegral<std::int8_t>(elem).value(), -25);

				ASSERT_FALSE(getIntegral<std::uint8_t>(elem));

				elem = cbor_array_get(map_elem_it->value, 2);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int16_t>(elem));
				EXPECT_EQ(getIntegral<std::int16_t>(elem).value(), -256);

				ASSERT_FALSE(getIntegral<std::uint8_t>(elem));
				ASSERT_FALSE(getIntegral<std::int8_t>(elem));
			}
				break;
			case 256:
			{
				EXPECT_TRUE(getIntegral<std::uint16_t>(map_elem_it->key));

				ASSERT_TRUE(cbor_isa_array(map_elem_it->value));
				ASSERT_TRUE(cbor_array_is_definite(map_elem_it->value));
				ASSERT_EQ(cbor_array_size(map_elem_it->value), 3);

				auto elem = cbor_array_get(map_elem_it->value, 0);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::uint16_t>(elem));
				EXPECT_EQ(getIntegral<std::uint16_t>(elem).value(), 65535);

				ASSERT_FALSE(getIntegral<std::uint8_t>(elem));

				elem = cbor_array_get(map_elem_it->value, 1);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int16_t>(elem));
				EXPECT_EQ(getIntegral<std::int16_t>(elem).value(), -257);

				ASSERT_FALSE(getIntegral<std::uint16_t>(elem));

				elem = cbor_array_get(map_elem_it->value, 2);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int32_t>(elem));
				EXPECT_EQ(getIntegral<std::int32_t>(elem).value(), -65536);

				ASSERT_FALSE(getIntegral<std::uint16_t>(elem));
				ASSERT_FALSE(getIntegral<std::int16_t>(elem));
			}
				break;
			case 65536:
			{
				EXPECT_TRUE(getIntegral<std::uint32_t>(map_elem_it->key));

				ASSERT_TRUE(cbor_isa_array(map_elem_it->value));
				ASSERT_TRUE(cbor_array_is_definite(map_elem_it->value));
				ASSERT_EQ(cbor_array_size(map_elem_it->value), 3);

				auto elem = cbor_array_get(map_elem_it->value, 0);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::uint32_t>(elem));
				EXPECT_EQ(getIntegral<std::uint32_t>(elem).value(), 4294967295);

				ASSERT_FALSE(getIntegral<std::uint16_t>(elem));

				elem = cbor_array_get(map_elem_it->value, 1);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int32_t>(elem));
				EXPECT_EQ(getIntegral<std::int32_t>(elem).value(), -65537);

				ASSERT_FALSE(getIntegral<std::uint32_t>(elem));

				elem = cbor_array_get(map_elem_it->value, 2);
				EXPECT_TRUE(cbor_is_int(elem));
				ASSERT_TRUE(getIntegral<std::int64_t>(elem));
				EXPECT_EQ(getIntegral<std::int64_t>(elem).value(), -4294967296);

				ASSERT_FALSE(getIntegral<std::uint64_t>(elem));
				ASSERT_FALSE(getIntegral<std::int32_t>(elem));
			}
				break;
			}
		}
	}

	TEST(CBOR_TEST, CBOR_String1)
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::ex_CBOR_string1);

		EXPECT_TRUE(cbor);

		auto array_data = getArray(cbor);
		ASSERT_TRUE(array_data);
		ASSERT_EQ(array_data.value().size(), 2);

		auto string1 = getString(array_data->at(0));
		ASSERT_TRUE(string1);
		ASSERT_EQ(string1->size(), 10);
		ASSERT_EQ(*string1, "qwertyuiop"s);

		auto string2 = getString(array_data->at(1));
		ASSERT_TRUE(string2);
		ASSERT_EQ(string2->size(), 12);
		ASSERT_EQ(*string2, "1qaz5tgb9ol."s);
	}

	TEST(CBOR_TEST, CBOR_Map_Array1) 
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::ex_CBOR_map_array1);

		ASSERT_TRUE(cbor);

		auto map_array = getMapArray(cbor);
		ASSERT_TRUE(map_array);

		std::set<long long> expected_keys{ 0, 24, 256, 65536 };
		std::set<long long> keys{};

		for (auto&& map_elem : *map_array)
		{
			auto key = getIntegral<long long>(map_elem->key);
			ASSERT_TRUE(key);

			keys.insert(*key);
			EXPECT_TRUE(expected_keys.contains(*key));

			auto array = getArray(map_elem->value);
			ASSERT_TRUE(array);
			EXPECT_EQ(array->size(), 3);
		}

		EXPECT_EQ(expected_keys, keys);
	}

	TEST(CBOR_TEST, CBOR_Map1)
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::indefinite_map1);

		ASSERT_TRUE(cbor);

		auto map_array = getMapArray(cbor);
		ASSERT_FALSE(map_array);
		ASSERT_TRUE(cbor_isa_map(cbor));
	}

	TEST(CBOR_TEST, CBOR_Map2)
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::indefinite_map2);

		ASSERT_FALSE(cbor);
	}

	TEST(CBOR_TEST, CBOR_Array1)
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::indefinite_array1);

		ASSERT_TRUE(cbor);

		auto map_array = getMapArray(cbor);
		ASSERT_FALSE(map_array);
		ASSERT_TRUE(cbor_isa_array(cbor));
	}

	TEST(CBOR_TEST, CBOR_Array2)
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::indefinite_array2);

		ASSERT_FALSE(cbor);
	}

	TEST(CBOR_TEST, CBOR_BinArray1)
	{
		using namespace std::string_literals;
		auto [cbor, result] = CBORHandle::fromBin(helpers::bin_array);

		ASSERT_TRUE(cbor);

		auto byte_array = getByteString(cbor);
		ASSERT_TRUE(byte_array);

		EXPECT_EQ(byte_array, helpers::bin_array_raw);
	}
}