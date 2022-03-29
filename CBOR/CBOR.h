#pragma once

#include <memory>
#include <vector>
#include <cstddef>
#include <optional>
#include <string>
#include <iterator>
#include <type_traits>

namespace webauthn::CBOR
{

#include <cbor.h>

	class CBORHandle
	{
	public:
		CBORHandle() = default;
		CBORHandle(cbor_item_t* cbor_root) : cbor_root{ cbor_root } {}

		CBORHandle(CBORHandle& cbor_handle) noexcept {
			cbor_root = cbor_handle.cbor_root;
			if (cbor_root)
			{
				cbor_incref(cbor_root);
			}
		}

		CBORHandle(CBORHandle&& cbor_handle) noexcept {
			cbor_root = cbor_handle.cbor_root;
			cbor_handle.cbor_root = nullptr;
		}

		CBORHandle& operator=(CBORHandle& cbor_handle) noexcept {
			if (cbor_root)
			{
				cbor_decref(&cbor_root);
			}

			cbor_root = cbor_handle.cbor_root;
			if (cbor_root)
			{
				cbor_incref(cbor_root);
			}
		}

		CBORHandle& operator=(CBORHandle&& cbor_handle) noexcept {
			if (cbor_root)
			{
				cbor_decref(&cbor_root);
			}

			cbor_root = cbor_handle.cbor_root;
			cbor_handle.cbor_root = nullptr;
		}

		~CBORHandle() {
			if (cbor_root)
			{
				cbor_decref(&cbor_root);
			}
		}

		//CBORHandle may have cbor_root == nullptr
		static std::pair<CBORHandle, cbor_load_result> fromBin(const std::vector<std::byte>& data);

		cbor_item_t* root()
		{
			return cbor_root;
		}

		bool good() const noexcept {
			return cbor_root != nullptr;
		}

		operator bool() const noexcept {
			return good();
		}

		operator cbor_item_t* () const noexcept {
			return cbor_root;
		}

	private:
		cbor_item_t* cbor_root{ nullptr };
	};

	template<std::integral T>
	std::optional<T> getIntegral(cbor_item_t* item)
	{
		if (!cbor_is_int(item))
		{
			return {};
		}

		bool is_positive = cbor_isa_uint(item);
		auto uint_value = cbor_get_int(item);

		//Chek if T is has same sign

		if (std::is_unsigned_v<T> && !is_positive)
		{
			return {};
		}

		if (!is_positive)
		{
			std::make_signed_t<decltype(uint_value)> int_value = uint_value;
			int_value = -int_value - 1;

			T value = static_cast<T>(int_value);

			if (static_cast<decltype(int_value)>(value) != int_value)
			{
				return {};
			}

			return value;
		}

		T value = static_cast<T>(uint_value);
		if (static_cast<decltype(uint_value)>(value) != uint_value)
		{
			return {};
		}

		return value;
	}

	std::optional<std::vector<cbor_pair*>> getMapArray(cbor_item_t* item);

	std::optional<std::string> getString(cbor_item_t* item);

	std::optional<std::vector<std::byte>> getByteString(cbor_item_t* item);

	std::optional<std::vector<cbor_item_t*>> getArray(cbor_item_t* item);
}