#include "CBORLib.h"

#include <algorithm>
#include <cstdlib>
#include <span>
#include <ranges>

webauthn::CBOR::CBORHandle::CBORHandle(CBORHandle& cbor_handle) noexcept {
	cbor_root = cbor_handle.cbor_root;
	if (cbor_root)
	{
		cbor_incref(cbor_root);
	}
}

webauthn::CBOR::CBORHandle::CBORHandle(webauthn::CBOR::CBORHandle&& cbor_handle) noexcept {
	cbor_root = cbor_handle.cbor_root;
	cbor_handle.cbor_root = nullptr;
}

webauthn::CBOR::CBORHandle& webauthn::CBOR::CBORHandle::operator=(CBORHandle& cbor_handle) noexcept {
	if (cbor_root)
	{
		cbor_decref(&cbor_root);
	}

	cbor_root = cbor_handle.cbor_root;
	if (cbor_root)
	{
		cbor_incref(cbor_root);
	}

	return *this;
}

webauthn::CBOR::CBORHandle& webauthn::CBOR::CBORHandle::operator=(CBORHandle&& cbor_handle) noexcept {
	if (cbor_root)
	{
		cbor_decref(&cbor_root);
	}

	cbor_root = cbor_handle.cbor_root;

	return *this;
}

webauthn::CBOR::CBORHandle::~CBORHandle() {
	if (cbor_root)
	{
		cbor_decref(&cbor_root);
	}
}

std::pair<webauthn::CBOR::CBORHandle, webauthn::CBOR::cbor_load_result> webauthn::CBOR::CBORHandle::fromBin(const unsigned char* data, std::size_t data_size)
{
	cbor_load_result result{};
	CBORHandle handle = cbor_load(data, data_size, &result);

	return { handle, result };
}

std::optional<std::vector<std::byte>> webauthn::CBOR::toBin(const cbor_item_t* item)
{
	if (!item)
		return {};

	std::unique_ptr<unsigned char, decltype([](unsigned char* ptr) {
		std::free(ptr);
		})> buffer{};
	unsigned char *tmp_buffer{ nullptr };
	std::size_t size{};
	auto length = cbor_serialize_alloc(item, &tmp_buffer, &size);
	buffer.reset(tmp_buffer);

	if (!buffer)
		return {};

	std::vector<std::byte> data{};
	std::ranges::transform(std::span{ buffer.get(), length }, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

	return data;
}

std::optional<std::vector<webauthn::CBOR::cbor_pair*>> webauthn::CBOR::getMapArray(const webauthn::CBOR::cbor_item_t* item)
{
	if (!item || !cbor_isa_map(item) || !cbor_map_is_definite(item))
	{
		return {};
	}

	auto size = cbor_map_size(item);
	auto ptr = cbor_map_handle(item);
	std::vector<cbor_pair*> map{};
	std::ranges::copy(std::span{ ptr, size } | std::views::transform([](cbor_pair& x) { return &x; }), std::back_inserter(map));

	return { map };
}

std::optional<std::string> webauthn::CBOR::getString(const webauthn::CBOR::cbor_item_t* item)
{
	if (!item || !cbor_isa_string(item) || !cbor_string_is_definite(item))
	{
		return {};
	}

	auto size = cbor_string_length(item);
	auto ptr = cbor_string_handle(item);
	std::string text{};
	std::ranges::copy(std::span{ ptr, size }, std::back_inserter(text));

	return text;
}

std::optional<std::vector<std::byte>> webauthn::CBOR::getByteString(const cbor_item_t* item)
{
	if (!item || !cbor_isa_bytestring(item) || !cbor_bytestring_is_definite(item))
	{
		return {};
	}

	auto size = cbor_bytestring_length(item);
	auto ptr = cbor_bytestring_handle(item);
	std::vector<std::byte> data{};

	std::ranges::copy(std::span{ ptr, size } | std::views::transform([](auto x) {return static_cast<std::byte>(x); }), std::back_inserter(data));

	return data;
}

std::optional<std::vector<webauthn::CBOR::cbor_item_t*>> webauthn::CBOR::getArray(const webauthn::CBOR::cbor_item_t* item)
{
	if (!item || !cbor_isa_array(item) || !cbor_array_is_definite(item))
	{
		return {};
	}

	auto size = cbor_array_size(item);
	auto ptr = cbor_array_handle(item);

	std::vector<cbor_item_t*> array{};
	std::ranges::copy(std::span{ ptr, size }, std::back_inserter(array));

	return array;
}
