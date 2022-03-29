#include "CBOR.h"

#include <algorithm>

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
	std::generate_n(std::back_inserter(map), size, [elem_ptr = ptr]() mutable { return elem_ptr++; });

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
	std::copy_n(ptr, size, std::back_inserter(text));

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
	for (std::size_t i = 0; i < size; i++, ptr++)
	{
		data.push_back(static_cast<std::byte>(*ptr));
	}

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
	std::copy_n(ptr, size, std::back_inserter(array));

	return array;
}
