#pragma once

#include <array>
#include <vector>
#include <iterator>
#include <concepts>
#include <span>
#include <ranges>
#include <algorithm>

namespace webauthn::crypto
{
	namespace hash_helpers
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
			std::is_default_constructible_v<T>;
			requires Byte<typename T::value_type>;
		};

		template<typename T, std::size_t N>
		concept FixedContainer = requires(T a)
		{
			std::size(a) == N;
			std::is_default_constructible_v<T>;
			requires Byte<typename T::value_type>;
		};

		static constexpr std::size_t SHA1_digest_size = 20;
		static constexpr std::size_t SHA256_digest_size = 32;
		static constexpr std::size_t SHA384_digest_size = 48;
		static constexpr std::size_t SHA512_digest_size = 64;
	}

	class hash
	{
	public:
		template<typename Out = std::array<std::byte, hash_helpers::SHA1_digest_size>, typename Range>
			requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA1_digest_size>) && std::ranges::contiguous_range<Range>
		static inline Out SHA1(Range&& range);

		template<typename Out = std::array<std::byte, hash_helpers::SHA256_digest_size>, typename Range>
			requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA256_digest_size>) && std::ranges::contiguous_range<Range>
		static inline Out SHA256(Range&& range);

		template<typename Out = std::array<std::byte, hash_helpers::SHA384_digest_size>, typename Range>
			requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA384_digest_size>) && std::ranges::contiguous_range<Range>
		static inline Out SHA384(Range&& range);

		template<typename Out = std::array<std::byte, hash_helpers::SHA512_digest_size>, typename Range>
			requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA512_digest_size>) && std::ranges::contiguous_range<Range>
		static inline Out SHA512(Range&& range);

		template<std::size_t N = 64, typename Out = std::array<std::byte, N>, typename Range1, typename Range2>
			requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, N>) && std::ranges::contiguous_range<Range1> && std::ranges::contiguous_range<Range2>
		static inline Out PBKDF2(Range1&& passw, Range2&& salt, int iteration = 20000);

	private:
		static std::array<std::byte, hash_helpers::SHA1_digest_size> SHA1_internal(const std::span<const unsigned char>& data);
		static std::array<std::byte, hash_helpers::SHA256_digest_size> SHA256_internal(const std::span<const unsigned char>& data);
		static std::array<std::byte, hash_helpers::SHA384_digest_size> SHA384_internal(const std::span<const unsigned char>& data);
		static std::array<std::byte, hash_helpers::SHA512_digest_size> SHA512_internal(const std::span<const unsigned char>& data);
		static std::vector<std::byte> PBKDF2_internal(const std::span<const char>& passw, const std::span<const unsigned char>& salt, int iteration, int keylen);
	};

	template<typename Out, typename Range>
		requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA1_digest_size>) && std::ranges::contiguous_range<Range>
	inline Out hash::SHA1(Range&& range)
	{
		auto hash = SHA1_internal({ reinterpret_cast<const unsigned char*>(std::data(range)), std::size(range) });

		if constexpr (std::is_same_v<Out, decltype(hash)>)
		{
			return hash;
		}
		else
		{
			Out out{};
			if constexpr (hash_helpers::Container<Out>)
			{
				std::ranges::transform(hash, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}
			else
			{
				std::ranges::transform(hash, std::begin(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}

			return out;
		}
	}

	template<typename Out, typename Range>
		requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA256_digest_size>) && std::ranges::contiguous_range<Range>
	inline Out hash::SHA256(Range&& range)
	{
		auto hash = SHA256_internal({ reinterpret_cast<const unsigned char*>(std::data(range)), std::size(range) });

		if constexpr (std::is_same_v<Out, decltype(hash)>)
		{
			return hash;
		}
		else
		{
			Out out{};
			if constexpr (hash_helpers::Container<Out>)
			{
				std::ranges::transform(hash, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}
			else
			{
				std::ranges::transform(hash, std::begin(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}

			return out;
		}
	}

	template<typename Out, typename Range>
		requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA384_digest_size>) && std::ranges::contiguous_range<Range>
	inline Out hash::SHA384(Range&& range)
	{
		auto hash = SHA384_internal({ reinterpret_cast<const unsigned char*>(std::data(range)), std::size(range) });

		if constexpr (std::is_same_v<Out, decltype(hash)>)
		{
			return hash;
		}
		else
		{
			Out out{};
			if constexpr (hash_helpers::Container<Out>)
			{
				std::ranges::transform(hash, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}
			else
			{
				std::ranges::transform(hash, std::begin(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}

			return out;
		}
	}

	template<typename Out, typename Range>
		requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, hash_helpers::SHA512_digest_size>) && std::ranges::contiguous_range<Range>
	inline Out hash::SHA512(Range&& range)
	{
		auto hash = SHA512_internal({ reinterpret_cast<const unsigned char*>(std::data(range)), std::size(range) });

		if constexpr (std::is_same_v<Out, decltype(hash)>)
		{
			return hash;
		}
		else
		{
			Out out{};
			if constexpr (hash_helpers::Container<Out>)
			{
				std::ranges::transform(hash, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}
			else
			{
				std::ranges::transform(hash, std::begin(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}

			return out;
		}
	}

	template<std::size_t N, typename Out, typename Range1, typename Range2>
		requires (hash_helpers::Container<Out> || hash_helpers::FixedContainer<Out, N>) && std::ranges::contiguous_range<Range1> && std::ranges::contiguous_range<Range2>
	inline Out hash::PBKDF2(Range1&& passw, Range2&& salt, int iteration)
	{
		auto hash = PBKDF2_internal({ reinterpret_cast<const char*>(std::data(passw)), std::size(passw) }, 
			{ reinterpret_cast<const unsigned char*>(std::data(salt)), std::size(salt) }, iteration, N);

		if constexpr (std::is_same_v<Out, decltype(hash)>)
		{
			return hash;
		}
		else
		{
			Out out{};
			if constexpr (hash_helpers::Container<Out>)
			{
				std::ranges::transform(hash, std::back_inserter(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}
			else
			{
				std::ranges::transform(hash, std::begin(out), [](auto&& x) { return static_cast<Out::value_type>(x); });
			}

			return out;
		}
	}
}