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

	namespace helpers
	{
		template<typename T>
		static inline constexpr bool is_byte()
		{
			using clear_T = std::remove_cv_t<T>;
			return std::is_same_v<clear_T, std::byte> || std::is_same_v<clear_T, char> || std::is_same_v<clear_T, unsigned char>;
		}

		template<typename T>
		concept Byte = requires(T t)
		{
			is_byte<T>;
		};
	}

	class CBORHandle
	{
	public:
		CBORHandle() = default;
		CBORHandle(cbor_item_t* cbor_root) : cbor_root{ cbor_root } {}
		CBORHandle(CBORHandle& cbor_handle) noexcept;
		CBORHandle(CBORHandle&& cbor_handle) noexcept;
		CBORHandle& operator=(CBORHandle& cbor_handle) noexcept;
		CBORHandle& operator=(CBORHandle&& cbor_handle) noexcept;
		~CBORHandle();

		//CBORHandle may have cbor_root == nullptr
		template<std::ranges::contiguous_range Range>
		requires helpers::Byte<std::iter_value_t<Range>>
		static inline std::pair<CBORHandle, cbor_load_result> fromBin(Range&& range);

		cbor_item_t* root() noexcept
		{
			return cbor_root;
		}

		const cbor_item_t* root() const noexcept
		{
			return cbor_root;
		}

		cbor_item_t* release() noexcept {
			auto root = cbor_root;
			cbor_root = nullptr;
			return root;
		}

		bool good() const noexcept {
			return cbor_root != nullptr;
		}

		operator bool() const noexcept {
			return good();
		}

		operator const cbor_item_t* () const noexcept {
			return cbor_root;
		}

		operator cbor_item_t* () noexcept {
			return cbor_root;
		}

	protected:
		static std::pair<CBORHandle, cbor_load_result> fromBin(const unsigned char* data, std::size_t data_size);

	private:
		cbor_item_t* cbor_root{ nullptr };
	};

	template<std::ranges::contiguous_range Range>
	requires helpers::Byte<std::iter_value_t<Range>>
	inline std::pair<CBORHandle, cbor_load_result> webauthn::CBOR::CBORHandle::fromBin(Range&& range)
	{
		return fromBin(reinterpret_cast<const unsigned char*>(std::ranges::data(range)), std::size(range));
	}

	template<std::integral T>
	std::optional<T> getIntegral(const cbor_item_t* item)
	{
		if (!item || !cbor_is_int(item))
		{
			return {};
		}

		const bool is_positive = cbor_isa_uint(item);
		const auto uint_value = cbor_get_int(item);

		//Chek if T has same sign
		if constexpr (std::is_unsigned_v<T>)
		{
			if (!is_positive)
			{
				return {};
			}
		}

		if (!is_positive)
		{
			std::make_signed_t<std::decay_t<decltype(uint_value)>> int_value = uint_value;
			int_value = -int_value - 1;

			T value = static_cast<T>(int_value);

			if (static_cast<decltype(int_value)>(value) != int_value)
			{
				return {};
			}

			return value;
		}

		const T value = static_cast<T>(uint_value);
		if (static_cast<decltype(uint_value)>(value) != uint_value)
		{
			return {};
		}

		return value;
	}

	std::optional<std::vector<std::byte>> toBin(const cbor_item_t* item);

	std::optional<std::vector<cbor_pair*>> getMapArray(const cbor_item_t* item);

	std::optional<std::string> getString(const cbor_item_t* item);

	std::optional<std::vector<std::byte>> getByteString(const cbor_item_t* item);

	std::optional<std::vector<cbor_item_t*>> getArray(const cbor_item_t* item);

}