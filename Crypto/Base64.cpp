#include "Base64.h"

#include <openssl/evp.h>

#include <memory>

namespace helpers
{
	using encode_ctx_ptr = std::unique_ptr<EVP_ENCODE_CTX, decltype([](EVP_ENCODE_CTX *ptr) {
		EVP_ENCODE_CTX_free(ptr);
		})>;
}

std::string webauthn::crypto::base64::toBase64_internal(const std::span<const unsigned char>& data)
{
	constexpr std::size_t encoded_block_size = 66; //64 bytes + 1 newline + 1 NULL
	constexpr std::size_t block_size = 48;

	std::vector<unsigned char> block_buffer{};
	block_buffer.resize(encoded_block_size);
	int witten{};

	std::string encoded_data{};

	helpers::encode_ctx_ptr ctx{ EVP_ENCODE_CTX_new() };
	EVP_EncodeInit(ctx.get());

	//Only encode one block per iteration
	std::size_t offset = 0;
	for (; offset < std::size(data); offset += block_size)
	{
		const auto actual_block_size = std::min({ block_size, std::size(data) - offset });
		const auto success = EVP_EncodeUpdate(ctx.get(), std::data(block_buffer), &witten, std::data(data) + offset, static_cast<int>(actual_block_size));
		if (!success)
			return {};

		std::ranges::transform(block_buffer | std::views::take(witten) | std::views::filter([](auto x) { return x != '\n'; }), std::back_inserter(encoded_data), [](auto x) { return static_cast<char>(x); });
	}

	EVP_EncodeFinal(ctx.get(), std::data(block_buffer), &witten);
	std::ranges::transform(block_buffer | std::views::take(witten) | std::views::filter([](auto x) { return x != '\n'; }), std::back_inserter(encoded_data), [](auto x) { return static_cast<char>(x); });

	return encoded_data;
}

std::optional<std::vector<std::byte>> webauthn::crypto::base64::fromBase64_internal(const std::span<const unsigned char>& data)
{
	constexpr std::size_t decoded_block_size = 20 * 3; //64 bytes + 1 newline + 1 NULL
	constexpr std::size_t block_size = 20 * 4;

	std::vector<unsigned char> block_buffer{};
	block_buffer.resize(decoded_block_size);
	int witten{};

	std::vector<std::byte> decoded_data{};

	helpers::encode_ctx_ptr ctx{ EVP_ENCODE_CTX_new() };
	EVP_DecodeInit(ctx.get());

	//Only encode one block per iteration
	std::size_t offset = 0;
	for (; offset < std::size(data); offset += block_size)
	{
		const auto actual_block_size = std::min({ block_size, std::size(data) - offset });
		const auto success = EVP_DecodeUpdate(ctx.get(), std::data(block_buffer), &witten, std::data(data) + offset, static_cast<int>(actual_block_size));
		if (success == -1)
			return {};

		std::ranges::transform(block_buffer | std::views::take(witten), std::back_inserter(decoded_data), [](auto x) { return static_cast<std::byte>(x); });
	}

	const auto success = EVP_DecodeFinal(ctx.get(), std::data(block_buffer), &witten);
	if (success == -1)
		return {};

	std::ranges::transform(block_buffer | std::views::take(witten), std::back_inserter(decoded_data), [](auto x) { return static_cast<std::byte>(x); });

	return std::make_optional(std::move(decoded_data));
}
