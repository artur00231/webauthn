#include "Libfido2Authenticator.h"

#include <memory>
#include <unordered_map>
#include <algorithm>

#include <fido.h>

namespace webauthn::impl::helpers
{
	using device_ptr = std::unique_ptr<fido_dev_t, decltype([](fido_dev_t* ptr)
		{ if (ptr)
			{
				//If device is already closed, nothing will happen
				fido_dev_close(ptr);
				fido_dev_free(&ptr);
			}
		})>;
	using fido_cred_ptr = std::unique_ptr < fido_cred_t, decltype([](fido_cred_t* ptr) {
		fido_cred_free(&ptr);
		}) > ;
	using fido_assert_ptr = std::unique_ptr < fido_assert_t, decltype([](fido_assert_t* ptr) {
		fido_assert_free(&ptr);
		}) > ;

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
		std::ranges::transform(extensions, std::back_inserter(extensions_str), [](auto ptr) { return std::string{ ptr }; });

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

	//Returns empty pointer if device cannot be opened
	device_ptr openFido2Device(const std::string& path)
	{
		device_ptr device{ fido_dev_new() };

		if (!device)
		{
			return {};
		}

		auto result = fido_dev_open(device.get(), path.c_str());
		if (result != FIDO_OK)
		{
			return {};
		}

		if (!fido_dev_is_fido2(device.get()))
		{
			return {};
		}

		return device;
	}
}

std::optional<webauthn::impl::Libfido2Authenticator> webauthn::impl::Libfido2Authenticator::createLibfido2Authenticator(std::string path, Libfido2Token token)
{
	auto device = helpers::openFido2Device(path);
	if (!device)
		return {};

	std::shared_ptr<fido_cbor_info_t> device_info_raw{ fido_cbor_info_new(), [](fido_cbor_info_t* ptr)
		{
			if (ptr) fido_cbor_info_free(&ptr);
		}
	};
	if (!device_info_raw)
		return {};

	if (fido_dev_get_cbor_info(device.get(), device_info_raw.get()) != FIDO_OK)
		return {};

	Libfido2Authenticator authenticator{};

	authenticator.path = path;

	authenticator.has_pin = fido_dev_has_pin(device.get());
	authenticator.has_uv = fido_dev_has_uv(device.get());

	authenticator.is_winhello = fido_dev_is_winhello(device.get());

	authenticator.supported.cred_prot = fido_dev_supports_cred_prot(device.get());
	authenticator.supported.credman = fido_dev_supports_credman(device.get());
	authenticator.supported.permissions = fido_dev_supports_permissions(device.get());
	authenticator.supported.pin = fido_dev_supports_pin(device.get());
	authenticator.supported.uv = fido_dev_supports_uv(device.get());

	auto algorithms_raw = helpers::getAvaiablePKAlgorithms(device_info_raw);
	std::ranges::copy(algorithms_raw | std::views::filter([](auto&& x) { return crypto::COSE::isCOSE_ALGORITHM(x); }) |
		std::views::transform([](auto&& x) { return static_cast<crypto::COSE::COSE_ALGORITHM>(x); }),
		std::back_inserter(authenticator.algorithms));

	auto extensions_raw = helpers::getAvaiableExtensions(device_info_raw);
	std::unordered_map<std::string, std::optional<EXTENSION>> extension_map{};
	std::ranges::for_each(SupportedExtensions, [&extension_map](auto x) {
		extension_map[getExtensionText(x)] = x;
		});
	std::ranges::for_each(extensions_raw, [&extension_map, &authenticator](auto&& x) {
		extension_map[x].and_then([&authenticator](auto&& y) { authenticator.extensions.push_back(y); return std::optional<bool>{}; });
		});

	auto options_raw = helpers::getAvaiableOptions(device_info_raw);
	std::unordered_map<std::string, std::optional<OPTION>> option_map{};
	std::ranges::for_each(SupportedOptions, [&option_map](auto x) {
		option_map[getOptionText(x)] = x;
		});
	std::ranges::for_each(options_raw, [&option_map, &authenticator](auto&& x) {
		option_map[x.first].and_then([&authenticator, &x](auto&& y) { authenticator.options.emplace_back(y, x.second); return std::optional<bool>{}; });
		});

	if (authenticator.winhello() && authenticator.algorithms.empty())
	{
		//No information avaiable
		//Add all posible algorithms (RS256 should be supported internaly)
		std::ranges::copy(Libfido2Authenticator::supported_algorithms, std::back_inserter(authenticator.algorithms));
	}

	
	return authenticator;
}

webauthn::impl::Libfido2Authenticator::MakeCredentialLibfido2Result webauthn::impl::Libfido2Authenticator::makeCredential(Libfido2Token token, const UserData& user, const RelyingParty& rp, const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	auto device = helpers::openFido2Device(path);
	if (!device)
		return { .success = FIDO_ERR_INVALID_ARGUMENT };

	helpers::fido_cred_ptr credential{ fido_cred_new() };
	if (!credential)
		return { .success = FIDO_ERR_INTERNAL };

	//TYPE
	//ONY ACCEPTED: COSE_ES256, COSE_RS256,  COSE_EDDSA
	if (!getChosenAlgorithm())
		return { .success = FIDO_ERR_INVALID_ARGUMENT };

	if (auto success = fido_cred_set_type(credential.get(), std::to_underlying(*getChosenAlgorithm())); success != FIDO_OK)
		return { .success = success };

	//CLIENT DATA
	if (auto success = fido_cred_set_clientdata(credential.get(), reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size()); success != FIDO_OK)
		return { .success = success };

	//RELYING PARTY
	//_, id, name
	if (auto success = fido_cred_set_rp(credential.get(), rp.ID.c_str(), rp.name.c_str()); success != FIDO_OK)
		return { .success = success };

	//USER
	//_, id, id_size, name, display name, icon
	if (auto success = fido_cred_set_user(credential.get(), reinterpret_cast<const unsigned char*>(user.ID.data()), user.ID.size(), user.name.c_str(),
		user.display_name.c_str(), nullptr); success != FIDO_OK)
		return { .success = success };
	
	//TIMEOUT
	if (auto success = fido_dev_set_timeout(device.get(), options.timeout); success != FIDO_OK)
		return { .success = success };

	//EXCLUDED CRIDENSIALS
	//resut = fido_cred_exclude(cred, credensial, credensial_size)
	//if (result != FIDO_OK)
	//{
	//	std::cerr << "Cannot fido_cred_set_type\n";
	//	return false;
	//}

	//resident/discoverable key and user verification attributes.
	//FIDO_OPT_OMIT - default
	//FIDO_OPT_FALSE - false
	//FIDO_OPT_TRUE - true
	//result = fido_cred_set_rk(cred, FIDO_OPT_FALSE);
	//if (result != FIDO_OK)
	//{
	//	std::cerr << "Cannot fido_cred_set_rk\n";
	//	return false;
	//}

	//result = fido_cred_set_uv(cred, FIDO_OPT_FALSE);
	//if (result != FIDO_OK)
	//{
	//	std::cerr << "Cannot fido_cred_set_uv\n";
	//	return false;
	//}

	//Setting FMT does nothing, this information is not transmited to authenticator
	//result = fido_cred_set_fmt(credential.get(), "none");
	//if (result != FIDO_OK)
	//	return {};

	//result = fido_cred_set_extensions(credential.get(), NULL);
	//if (result != FIDO_OK)
	//	return {};

	const auto success = fido_dev_make_cred(device.get(), credential.get(), password ? password->c_str() : nullptr);

	MakeCredentialLibfido2Result created_credential{};
	created_credential.success = success;

	if (success == FIDO_OK)
	{
		created_credential.format = fido_cred_fmt(credential.get());
		std::ranges::transform(std::span{ fido_cred_authdata_raw_ptr(credential.get()), fido_cred_authdata_raw_len(credential.get()) }, std::back_inserter(created_credential.authenticator_data),
			[](auto x) { return static_cast<std::byte>(x); });
		std::ranges::transform(std::span{ fido_cred_attstmt_ptr(credential.get()), fido_cred_attstmt_len(credential.get()) }, std::back_inserter(created_credential.attestation_statement),
			[](auto x) { return static_cast<std::byte>(x); });
	}
	else
	{
		fido_dev_cancel(device.get());
	}

	return created_credential;
}

webauthn::impl::Libfido2Authenticator::GetAssertionLibfido2Result webauthn::impl::Libfido2Authenticator::getAssertion(Libfido2Token token, const std::vector<CredentialId>& id, const RelyingParty& rp, const std::vector<std::byte>& challenge, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	auto device = helpers::openFido2Device(path);
	if (!device)
		return { .success = FIDO_ERR_INVALID_ARGUMENT };

	helpers::fido_assert_ptr assert{ fido_assert_new() };
	if (!assert)
		return { .success = FIDO_ERR_INTERNAL };

	//CLIENT DATA
	if (auto success = fido_assert_set_clientdata(assert.get(), reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size()); success != FIDO_OK)
		return { .success = success };

	//RELYING PARTY
	//_, id
	if (auto success = fido_assert_set_rp(assert.get(), rp.ID.c_str()); success != FIDO_OK)
		return { .success = success };

	//ALLOWED CREDENTIALS
	for (auto&& credential : id)
	{
		if (auto success = fido_assert_allow_cred(assert.get(), reinterpret_cast<const unsigned char*>(credential.id.data()), credential.id.size());
			success != FIDO_OK && aggresive_errors)
			return { .success = success };
	}

	//EXTENSIONS
	//result = fido_assert_set_extensions(assert, ext);
	//if (result != FIDO_OK)
	//	return {};

	//USER PRESENCE
	if (auto success = fido_assert_set_up(assert.get(), [&options](){
		switch (options.user_presence)
		{
		case USER_PRESENCE::REQUIRED:
			return FIDO_OPT_TRUE;
		case USER_PRESENCE::DISCOURAGED:
			return FIDO_OPT_FALSE;
		default:
			return FIDO_OPT_OMIT;
		}
		}()); success != FIDO_OK)
		return { .success = success };

	//USER VERIFICATION
	if (auto success = fido_assert_set_uv(assert.get(), [&options]() {
		switch (options.user_verification)
		{
		case USER_VERIFICATION::REQUIRED:
			return FIDO_OPT_TRUE;
		case USER_VERIFICATION::DISCOURAGED:
			return FIDO_OPT_FALSE;
		default:
			return FIDO_OPT_OMIT;
		}
		}()); success != FIDO_OK)
		return { .success = success };

	//TIMEOUT
	if (auto success = fido_dev_set_timeout(device.get(), options.timeout); success != FIDO_OK)
		return { .success = success };


	GetAssertionLibfido2Result get_assertion{};
	const auto success = fido_dev_get_assert(device.get(), assert.get(), password ? password->c_str() : nullptr);
	get_assertion.success = success;
	
	if (success == FIDO_OK)
	{
		const auto assert_count = fido_assert_count(assert.get());
		get_assertion.assert_datas.resize(assert_count);

		for (std::size_t i = 0; i < assert_count; i++)
		{
			auto& assert_datas = get_assertion.assert_datas[i];

			std::ranges::transform(std::span{ fido_assert_user_id_ptr(assert.get(), i), fido_assert_user_id_len(assert.get(), i) }, std::back_inserter(assert_datas.user_id),
				[](auto x) { return static_cast<std::byte>(x); });

			std::ranges::transform(std::span{ fido_assert_sig_ptr(assert.get(), i), fido_assert_sig_len(assert.get(), i) }, std::back_inserter(assert_datas.signature),
				[](auto x) { return static_cast<std::byte>(x); });

			std::ranges::transform(std::span{ fido_assert_authdata_ptr(assert.get(), i), fido_assert_authdata_len(assert.get(), i) }, std::back_inserter(assert_datas.cbor_authdata),
				[](auto x) { return static_cast<std::byte>(x); });
		}
	}
	else
	{
		fido_dev_cancel(device.get());
	}

	return get_assertion;
}

bool webauthn::impl::Libfido2Authenticator::supports(OPTION option) const noexcept
{
	auto it = std::ranges::find_if(options, [option](auto&& x) { return x.first == option; });
	if (it == options.end())
		return false;

	return it->second;
}

bool webauthn::impl::Libfido2Authenticator::supports(EXTENSION extension) const noexcept
{
	return std::ranges::find(extensions, extension) == extensions.end() ? false : true;
}