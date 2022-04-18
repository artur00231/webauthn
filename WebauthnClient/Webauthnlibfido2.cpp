#include "Webauthnlibfido2.h"

#include <fido.h>
#include <memory>
#include <format>
#include <ranges>
#include <utility>

namespace helpers
{
	static std::vector<int> getAvaiablePKAlgorithms(const std::shared_ptr<fido_cbor_info_t> info)
	{
		if (!info) return {};

		std::vector<int> algorithms{};

		auto num_of_algorithms = fido_cbor_info_algorithm_count(info.get());
		algorithms.reserve(num_of_algorithms);

		for (decltype(num_of_algorithms) i = 0; i < num_of_algorithms; i++)
		{
			algorithms.push_back(fido_cbor_info_algorithm_cose(info.get(), i));
		}

		return algorithms;
	}

	static std::vector<std::string> getAvaiableExtensions(const std::shared_ptr<fido_cbor_info_t> info)
	{
		if (!info) return {};

		auto extensions_length = fido_cbor_info_extensions_len(info.get());
		auto extensions_ptr = fido_cbor_info_extensions_ptr(info.get());

		std::vector<std::string> extensions_str{};

		const auto extensions = std::span{ extensions_ptr, extensions_length };

		for (const auto& extension : extensions)
		{
			extensions_str.push_back(extension);
		}

		return extensions_str;
	}

	static std::vector<std::pair<std::string, bool>> getAvaiableOptions(const std::shared_ptr<fido_cbor_info_t> info)
	{
		if (!info) return {};

		auto length = fido_cbor_info_options_len(info.get());
		auto n_ptr = fido_cbor_info_options_name_ptr(info.get());
		auto v_ptr = fido_cbor_info_options_value_ptr(info.get());

		const auto options_v = std::span{ v_ptr, length };
		const auto options_n = std::span{ n_ptr, length };

		std::vector<std::pair<std::string, bool>> options{};

		for (std::size_t i = 0; i < options_n.size(); i++)
		{
			options.emplace_back(options_n[i], options_v[i]);
		}

		return options;
	}
}

std::optional<webauthn::MakeCredentialResult> webauthn::impl::Webauthnlibfido2::makeCredential(const UserData& user, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
    return std::optional<MakeCredentialResult>();
}

std::optional<webauthn::GetAssertionResult> webauthn::impl::Webauthnlibfido2::getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
    return std::optional<GetAssertionResult>();
}

std::optional<std::vector<std::string>> webauthn::impl::Webauthnlibfido2::getAvaiableFidoDevices()
{
	std::size_t num_of_authenticators{};

	auto deleter = [max = max_num_of_authenticators](fido_dev_info_t* ptr)
	{
		if (ptr) fido_dev_info_free(&ptr, max);
	};

	std::unique_ptr<fido_dev_info_t, decltype(deleter)> authenticators_list{ nullptr, deleter };
	authenticators_list.reset(fido_dev_info_new(max_num_of_authenticators));

	if (!authenticators_list)
	{
		error("FIDO2: fido_dev_info_new");
		return {};
	}

	auto result = fido_dev_info_manifest(authenticators_list.get(), max_num_of_authenticators, &num_of_authenticators);
	if (result != FIDO_OK)
	{
		error("FIDO2: fido_dev_info_manifest");
		return {};
	}

	std::vector<std::string> authenticators{};

	for (std::size_t i = 0; i < num_of_authenticators; i++) {
		const fido_dev_info_t* device_info = fido_dev_info_ptr(authenticators_list.get(), i);

		if (!device_info)
		{
			error("FIDO2: fido_dev_info_ptr");
			return {};
		}

		authenticators.push_back(fido_dev_info_path(device_info));
	}

	return authenticators;
}

std::optional<webauthn::impl::Webauthnlibfido2::fido2_device_info> webauthn::impl::Webauthnlibfido2::getFido2DeviceInfo(const std::string& path)
{
	std::unique_ptr<fido_dev_t, decltype([](fido_dev_t* ptr)
		{ if (ptr)
			{
				//If device is already closed, nothing will happen
				fido_dev_close(ptr); 
				fido_dev_free(&ptr);
			}
		})> device{fido_dev_new()};

	if (!device)
	{
		error("FIDO2: fido_dev_new");
		return {};
	}

	auto result = fido_dev_open(device.get(), path.c_str());
	if (result != FIDO_OK)
	{
		error(std::format("Connot open device: {}", path));
		return {};
	}

	if (!fido_dev_is_fido2(device.get()))
	{
		return {};
	}

	std::shared_ptr<fido_cbor_info_t> device_info_raw{ fido_cbor_info_new(), [](fido_cbor_info_t* ptr)
		{
			if (ptr) fido_cbor_info_free(&ptr);
		}
	};

	result = fido_dev_get_cbor_info(device.get(), device_info_raw.get());
	if (result != FIDO_OK)
	{
		error(std::format("Connot get device info: {}", path));
		return {};
	}

	fido2_device_info device_info{};
	device_info.has_pin = fido_dev_has_pin(device.get());
	device_info.has_uv = fido_dev_has_uv(device.get());

	device_info.is_winhello = fido_dev_is_winhello(device.get());

	device_info.supports_cred_prot = fido_dev_supports_cred_prot(device.get());
	device_info.supports_credman = fido_dev_supports_credman(device.get());
	device_info.supports_permissions = fido_dev_supports_permissions(device.get());
	device_info.supports_pin = fido_dev_supports_pin(device.get());
	device_info.supports_uv = fido_dev_supports_uv(device.get());

	auto algorithms_raw = helpers::getAvaiablePKAlgorithms(device_info_raw);
	std::ranges::copy(algorithms_raw | std::views::filter([](auto&& x) { return crypto::COSE::isCOSE_ALGORITHM(x); }) |
		std::views::transform([](auto&& x) { return static_cast<crypto::COSE::COSE_ALGORITHM>(x); }),
		std::back_inserter(device_info.algorithms));

	auto extensions_raw = helpers::getAvaiableExtensions(device_info_raw);
	std::vector<std::pair<std::string, EXTENSION>> supported_extensions{};
	std::ranges::copy(SupportedExtensions | std::views::transform([](auto x) { return std::pair{ getExtensionText(x), x }; }), std::back_inserter(supported_extensions));
	std::ranges::copy(extensions_raw | std::views::transform([&supported_extensions](auto&& x) -> std::optional<EXTENSION> {
		auto it = std::ranges::find_if(supported_extensions, [&x](auto&& y) { return y.first == x; });
		if (it == supported_extensions.end())
		{
			return {};
		}
		else
		{
			return it->second;
		}
		}) | std::views::filter([](auto&& x) { return static_cast<bool>(x); }) | std::views::transform([](auto&& x) { return *x; }), std::back_inserter(device_info.extensions));

	auto options_raw = helpers::getAvaiableOptions(device_info_raw);
	std::vector<std::pair<std::string, OPTION>> supported_options{};
	std::ranges::copy(SupportedOptions | std::views::transform([](auto x) { return std::pair{ getOptionText(x), x }; }), std::back_inserter(supported_options));
	std::ranges::copy(options_raw | std::views::transform([&supported_options](auto&& x) -> std::optional<std::pair<OPTION, bool>> {
		auto it = std::ranges::find_if(supported_options, [&x](auto&& y) { return y.first == x.first; });
		if (it == supported_options.end())
		{
			return {};
		}
		else
		{
			return { { it->second, x.second } };
		}
		}) | std::views::filter([](auto&& x) { return static_cast<bool>(x); }) | std::views::transform([](auto&& x) { return *x; }), std::back_inserter(device_info.options));

	return { device_info };
}

void webauthn::impl::Webauthnlibfido2::error(std::string error_message)
{
	errors.push_back(error_message);
}
