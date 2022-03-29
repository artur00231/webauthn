#pragma once

#include <openssl/evp.h>

#include <vector>
#include <cstddef>
#include <string>
#include <exception>
#include <optional>
#include <algorithm>

namespace webauthn::crypto::base64
{
	namespace helpers
	{
		template<typename T>
		concept Container = requires(T a)
		{
			{ std::declval<T>().data() };
			{ std::declval<T>().size() } -> std::convertible_to<std::size_t>;
		};

		template<typename T>
		concept Copyable = requires(T a)
		{
			{ std::declval<T>().begin() };
			{ std::declval<T>().end() };
			std::is_convertible_v<typename T::value_type, char>;
		};

		template<typename T>
		concept Resizeable = requires(T a)
		{
			{ std::declval<T>().resize(std::declval<std::size_t>()) };
		};
	}

	template<typename In, typename Out = std::string>
	requires helpers::Container<std::add_const_t<In>> && helpers::Container<Out> && helpers::Resizeable<Out> && std::default_initializable<Out>
	Out toBase64(const In& data)
	{
		auto predicted_size = (data.size() / 3 + 1) * 4 + 1 /*NULL termination*/;
		Out out{};
		out.resize(predicted_size);

		std::size_t length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), 
			reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()));

		if (predicted_size < length + 1)
		{
			//Oh no
			//We just wrote somewhere where we are not supposed to

			//Uncomment std::terminate() to stop execution
			//std::terminate();
		}

		out.resize(length);
		return out;
	}

	template<typename Out, typename In = std::string>
		requires helpers::Container<std::add_const_t<In>> && helpers::Container<Out>&& helpers::Resizeable<Out> && std::default_initializable<Out>
	std::optional<Out> fromBase64(const In& data)
	{
		if (data.size() % 4 != 0)
		{
			return {};
		}

		auto predicted_size = (data.size() / 4) * 3;
		Out out{};
		out.resize(predicted_size);

		int length = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
			reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size()));

		if (length == 0 || length == -1)
		{
			return {};
		}

		if (predicted_size < length)
		{
			//Oh no
			//We just wrote somewhere where we are not supposed to

			//Uncomment std::terminate() to stop execution
			std::terminate();
		}

		out.resize(length);
		return out;
	}

	template<typename Out, typename In = std::string>
		requires helpers::Copyable<std::add_const_t<In>>&& helpers::Container<Out>&& helpers::Resizeable<Out>&& std::default_initializable<Out>
	std::optional<Out> fromBase64Fix(const In& data)
	{
		std::vector<char> data_fixed{};
		std::copy(data.begin(), data.end(), std::back_inserter(data_fixed));

		auto diff = 4 - data.size() % 4;
		diff = diff == 4 ? 0 : diff;

		for (decltype(diff) i = 0; i < diff; i++)
		{
			data_fixed.push_back('=');
		}

		std::for_each(data_fixed.begin(), data_fixed.end(), [](char& x) {
				if (x == '-') { 
					x = '+';
				} else if (x == '_') { 
					x = '/';
				} 
			});

		auto result = fromBase64<Out>(data_fixed);

		if (!result.has_value())
		{
			return {};
		}

		result->resize(result->size() - diff);

		return result;
	}
}