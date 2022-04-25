#include "CBOR.h"

#include <algorithm>
#include <span>
#include <ranges>

std::pair<webauthn::CBOR::CBORHandle, webauthn::CBOR::cbor_load_result> webauthn::CBOR::CBORHandle::fromBin(const std::vector<std::byte>& data)
{
	cbor_load_result result{};
	CBORHandle handle = cbor_load(reinterpret_cast<const unsigned char*>(data.data()), data.size(), &result);

	return { handle, result };
}

std::optional<std::vector<webauthn::CBOR::cbor_pair*>> webauthn::CBOR::getMapArray(webauthn::CBOR::cbor_item_t* item)
{
	if (!cbor_isa_map(item) || !cbor_map_is_definite(item))
	{
		return {};
	}

	auto size = cbor_map_size(item);
	auto ptr = cbor_map_handle(item);
	std::vector<cbor_pair*> map{};
	std::ranges::copy(std::span{ ptr, size } | std::views::transform([](cbor_pair& x) { return &x; }), std::back_inserter(map));

	return { map };
}

std::optional<std::string> webauthn::CBOR::getString(webauthn::CBOR::cbor_item_t* item)
{
	if (!cbor_isa_string(item) || !cbor_string_is_definite(item))
	{
		return {};
	}

	auto size = cbor_string_length(item);
	auto ptr = cbor_string_handle(item);
	std::string text{};
	std::ranges::copy(std::span{ ptr, size }, std::back_inserter(text));

	return text;
}

std::optional<std::vector<std::byte>> webauthn::CBOR::getByteString(cbor_item_t* item)
{
	if (!cbor_isa_bytestring(item) || !cbor_bytestring_is_definite(item))
	{
		return {};
	}

	auto size = cbor_bytestring_length(item);
	auto ptr = cbor_bytestring_handle(item);
	std::vector<std::byte> data{};

	std::ranges::copy(std::span{ ptr, size } | std::views::transform([](auto x) {return static_cast<std::byte>(x); }), std::back_inserter(data));

	return data;
}

std::optional<std::vector<webauthn::CBOR::cbor_item_t*>> webauthn::CBOR::getArray(webauthn::CBOR::cbor_item_t* item)
{
	if (!cbor_isa_array(item) || !cbor_array_is_definite(item))
	{
		return {};
	}

	auto size = cbor_array_size(item);
	auto ptr = cbor_array_handle(item);

	std::vector<cbor_item_t*> array{};
	std::ranges::copy(std::span{ ptr, size }, std::back_inserter(array));

	return array;
}
