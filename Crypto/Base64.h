#pragma once

#include <vector>
#include <string>
#include <exception>
#include <optional>
#include <algorithm>
#include <iterator>
#include <ranges>
#include <span>
#include <cctype>

namespace webauthn::crypto
{
	namespace base64_helpers
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

		template<typename T>
		concept Container = requires(T a)
		{
			{ a.push_back(std::declval<typename T::value_type>()) };
			std::is_destructible_v<T>;
			requires Byte<typename T::value_type>;
		};
	}

	class base64
	{
	public:
		template<typename Out = std::string, typename Range>
			requires base64_helpers::Container<Out> && std::ranges::contiguous_range<Range> && base64_helpers::Byte<std::iter_value_t<Range>>
		static inline Out toBase64(Range&& range);

		template<typename Out = std::vector<std::byte>, typename Range>
			requires base64_helpers::Container<Out> && std::ranges::contiguous_range<Range> && base64_helpers::Byte<std::iter_value_t<Range>>
		static inline std::optional<Out> fromBase64(Range&& range);

		template<typename Out = std::vector<std::byte>, typename Range>
			requires base64_helpers::Container<Out>  && std::ranges::contiguous_range<Range> && base64_helpers::Byte<std::iter_value_t<Range>>
		static inline std::optional<Out> fromBase64Url(Range&& data);
	private:
		static std::string toBase64_internal(const std::span<const unsigned char>& data);
		static std::optional<std::vector<std::byte>> fromBase64_internal(const std::span<const unsigned char>& data);
	};

	template<typename Out, typename Range>
	requires base64_helpers::Container<Out> && std::ranges::contiguous_range<Range> && base64_helpers::Byte<std::iter_value_t<Range>>
	inline Out base64::toBase64(Range&& range)
	{
		auto base64_encoded = toBase64_internal({ reinterpret_cast<const unsigned char*>(std::data(range)), std::size(range) });

		if constexpr (std::is_same_v<Out, decltype(base64_encoded)>)
		{
			return base64_encoded;
		}
		else
		{
			Out out{};
			std::ranges::transform(base64_encoded, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });

			return out;
		}
	}

	template<typename Out, typename Range>
		requires base64_helpers::Container<Out> && std::ranges::contiguous_range<Range> && base64_helpers::Byte<std::iter_value_t<Range>>
	inline std::optional<Out> base64::fromBase64(Range&& range)
	{
		auto binary_data = fromBase64_internal(std::span{ reinterpret_cast<const unsigned char*>(std::data(range)), std::size(range) });
		if (!binary_data)
			return {};

		if constexpr (std::is_same_v<Out, decltype(binary_data)>)
		{
			return std::make_optional(std::move(binary_data));
		}
		else
		{
			Out out{};
			std::ranges::transform(*binary_data, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });

			return std::make_optional(std::move(out));
		}
	}

	template<typename Out, typename Range>
		requires base64_helpers::Container<Out> && std::ranges::contiguous_range<Range> && base64_helpers::Byte<std::iter_value_t<Range>>
	inline std::optional<Out> base64::fromBase64Url(Range&& data)
	{
		std::vector<std::iter_value_t<Range>> data_fixed{};
		std::ranges::transform(data | std::views::filter([](auto x) {
			switch (x)
			{
			case '\n': [[fallthrough]];
			case ' ':
				return false;
			default:
				return true;
			}
			}), std::back_inserter(data_fixed), [](auto x) {
			switch (x)
			{
			case '-':
				return '+';
			case '_':
				return '/';
			case '.':
				return '=';
			default:
				return x;
			}
			});

		auto padding_size = (4 - (data_fixed.size() % 4)) % 4;
		while (padding_size --> 0) data_fixed.push_back(static_cast<std::iter_value_t<Range>>('='));

		return fromBase64<Out>(data_fixed);
	}
}