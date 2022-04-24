#include "Webauthnlibfido2.h"

#include "../CBOR/CBOR.h"
#include "../Webauthn/AuthenticatorData.h"

//TODO delete it
#include <iostream>

#include <fido.h>
#include <memory>
#include <format>
#include <ranges>
#include <utility>
#include <unordered_map>

namespace webauthn::impl::helpers
{
	using fido_cred_ptr = std::unique_ptr<fido_cred_t, decltype([](fido_cred_t* ptr) {
		fido_cred_free(&ptr);
	})>; 
	using fido_assert_ptr = std::unique_ptr<fido_assert_t, decltype([](fido_assert_t* ptr) {
		fido_assert_free(&ptr);
	})>; 

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

	//TODO clean it!!!!!!!!!!!
	std::optional<std::vector<std::byte>> makeAttestationObject(fido_cred_ptr&& credential, bool include_attestation)
	{
		static constexpr std::size_t AAGUID_offset = 37;
		static constexpr std::size_t AAGUID_size = 16;

		static constexpr std::size_t max_return_vector_size = /*2^*/28; //~268.4MB

		using namespace std::string_literals;
		auto format = fido_cred_fmt(credential.get());
		if (format == nullptr)
			return {};

		if (!include_attestation)
		{
			format = "none";
		}

		std::vector<std::byte> authdata{};
		std::ranges::transform(std::span{ fido_cred_authdata_raw_ptr(credential.get()), fido_cred_authdata_raw_len(credential.get()) }, std::back_inserter(authdata),
			[](auto&& x) { return static_cast<std::byte>(x); });

		//TODO clean fromBin
		auto authenticator_data = AuthenticatorData::fromBin(authdata);

		auto auth_attstmt_ptr = fido_cred_attstmt_ptr(credential.get());
		auto auth_attstmt_len = fido_cred_attstmt_len(credential.get());


		//If format == none then
		//Remove attstmt
		//Replace AAGUID with zeros
		if (format == "none"s)
		{
			//Replace AAGUID with zeros
			if (authenticator_data.attested_credential_data)
			{
				std::ranges::for_each(authenticator_data.attested_credential_data->AAGUID, [](std::byte& byte) { byte = std::byte{ 0 }; });
			}

			auth_attstmt_ptr = nullptr;
			auth_attstmt_len = 0;
		}

		authdata = authenticator_data.toBin();

		//Create AttestationObject
		//MAP 3
		// fmt
		// attStmt 
		// authData
		CBOR::CBORHandle handle{ CBOR::cbor_new_definite_map(3) };
		CBOR::cbor_map_add(handle,
			CBOR::cbor_pair{
				.key = CBOR::cbor_move(CBOR::cbor_build_string("fmt")),
				.value = CBOR::cbor_move(CBOR::cbor_build_string(format))
		});
		if (auth_attstmt_len == 0)
		{
			CBOR::cbor_map_add(handle,
				CBOR::cbor_pair{
					.key = CBOR::cbor_move(CBOR::cbor_build_string("attStmt")),
					.value = CBOR::cbor_move(CBOR::cbor_new_definite_map(0))
				});
		}
		else
		{
			std::vector<std::byte> attStmt{};
			std::ranges::transform(std::span{ auth_attstmt_ptr, auth_attstmt_len }, std::back_inserter(attStmt),
				[](auto&& x) { return static_cast<std::byte>(x); });

			auto [attStmt_handle, load_result] = CBOR::CBORHandle::fromBin(attStmt);
			if (load_result.error.code != CBOR::CBOR_ERR_NONE)
			{
				return {};
			}

			CBOR::cbor_map_add(handle,
				CBOR::cbor_pair{
					.key = CBOR::cbor_move(CBOR::cbor_build_string("attStmt")),
					.value = CBOR::cbor_move(attStmt_handle.release())
				});
		}

		CBOR::cbor_map_add(handle,
			CBOR::cbor_pair{
				.key = CBOR::cbor_move(CBOR::cbor_build_string("authData")),
				.value = CBOR::cbor_move(CBOR::cbor_build_bytestring(reinterpret_cast<const unsigned char*>(authdata.data()), authdata.size()))
			});

		std::vector<std::byte> attestation_object{};
		attestation_object.resize(128);

		//Try for sizes in [2**8, 2**9, 2**10, ..., 2**]
		for (std::size_t i = 8; i <= max_return_vector_size; i++)
		{
			auto attestation_objec_real_size = CBOR::cbor_serialize(handle, reinterpret_cast<unsigned char*>(attestation_object.data()), attestation_object.size());
			if (attestation_objec_real_size != 0)
			{
				//It's OK
				attestation_object.resize(attestation_objec_real_size);
				return attestation_object;
			}

			auto old_size = attestation_object.size();
			attestation_object.clear();
			attestation_object.resize(old_size * 2);
		}

		return {};
	}

	//TODO change it
	template<std::ranges::contiguous_range Range>
	requires std::is_same_v<std::byte, std::iter_value_t<Range>> || std::is_same_v<char, std::iter_value_t<Range>> || std::is_same_v<unsigned char, std::iter_value_t<Range>>
	std::optional<std::vector<std::byte>> unpackCBORByteString(Range && range)
	{
		std::vector<std::byte> data{};
		std::ranges::transform(range, std::back_inserter(data), [](auto x) { return static_cast<std::byte>(x); });

		auto [handle, load_result] = CBOR::CBORHandle::fromBin(data);
		if (!handle)
			return {};

		auto decoded_data = CBOR::getByteString(handle);
		if (!decoded_data)
			return {};
		return *decoded_data;
	}
}

std::optional<webauthn::MakeCredentialResult> webauthn::impl::Webauthnlibfido2::makeCredential(const UserData& user, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	//Start library
	fido_init(FIDO_DISABLE_U2F_FALLBACK);

	auto authenticator_to_use = getSuitableDevice(options);

	//Make credential using libfido2
	return makeCredential(*authenticator_to_use, user, rp, challange, password, options);
}

std::optional<webauthn::GetAssertionResult> webauthn::impl::Webauthnlibfido2::getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	//Start library
	fido_init(FIDO_DISABLE_U2F_FALLBACK);

	auto authenticator_to_use = getSuitableDevice(options);

	//Make credential using libfido2
	return getAssertion(*authenticator_to_use, id, rp, challange, password, options);
}

std::optional<std::vector<webauthn::impl::Libfido2Authenticator>> webauthn::impl::Webauthnlibfido2::getAvaiableFidoDevices()
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
		return {};
	}

	auto result = fido_dev_info_manifest(authenticators_list.get(), max_num_of_authenticators, &num_of_authenticators);
	if (result != FIDO_OK)
	{
		return {};
	}

	std::vector<Libfido2Authenticator> authenticators{};

	for (std::size_t i = 0; i < num_of_authenticators; i++) {
		const fido_dev_info_t* device_info = fido_dev_info_ptr(authenticators_list.get(), i);

		if (!device_info)
		{
			return {};
		}

		Libfido2Authenticator::createLibfido2Authenticator(fido_dev_info_path(device_info), Libfido2Token{}).and_then([&authenticators](auto&& authenticator)
			{
				authenticators.push_back(authenticator);
				return std::make_optional(authenticator);
			});
	}

	return authenticators;
}

std::optional<webauthn::impl::Libfido2Authenticator> webauthn::impl::Webauthnlibfido2::getUserSelectedDevice(const std::vector<Libfido2Authenticator>& authenticators)
{
	if (authenticators.empty())
	{
		return {};
	}

	using device_ptr = std::unique_ptr<fido_dev_t, decltype([](fido_dev_t* ptr) {
		fido_dev_free(&ptr); })>;

	std::vector<std::pair<device_ptr, std::reference_wrapper<const Libfido2Authenticator>>> fido2_devices;

	for (auto&& authenticator : authenticators)
	{
		device_ptr device{ fido_dev_new() };
		if (!device)
			return {};

		auto result = fido_dev_open(device.get(), authenticator.getPath().c_str());
		if (result != FIDO_OK)
		{
			return {};
		}

		fido2_devices.emplace_back(std::move(device), std::cref(authenticator));
	}

	//Start touch request
	for (const auto& [fido2_device, device_info] : fido2_devices)
	{
		auto result = fido_dev_get_touch_begin(fido2_device.get());
		if (result != FIDO_OK)
		{
			return {};
		}
	}

	std::optional<Libfido2Authenticator> selected_authenticator{};
	bool done{ false };

	auto wait_time_per_round = fido2_devices.size() * wait_time_device; //ms
	auto max_wait_rounds = max_wait_time * 1000 / wait_time_per_round;

	//Wait for touch
	for (decltype(max_wait_rounds) i = 0; i < max_wait_rounds && !done; i++)
	{
		//Find touched device
		for (const auto& [fido_device, authenticator] : fido2_devices)
		{
			int touched{};

			auto result = fido_dev_get_touch_status(fido_device.get(), &touched, wait_time_device);
			if (result != FIDO_OK)
			{
				done = true;
			}

			if (touched)
			{
				selected_authenticator = authenticator.get();
				done = true;
				break;
			}
		}
	}

	//Stop waiting for others
	for (const auto& [fido_device, path] : fido2_devices)
	{
		fido_dev_cancel(fido_device.get());
	}

	return selected_authenticator;
}

std::optional<webauthn::impl::Libfido2Authenticator> webauthn::impl::Webauthnlibfido2::getSuitableDevice(const WebAuthnOptions& options)
{
	//Search for appropriate FIDO2 authenticator 
	auto authenticators = getAvaiableFidoDevices();
	if (!authenticators)
	{
		return {};
	}

	if (authenticators->size() == 0)
	{
		user_error_msg = no_fido2_devices_err;
		return {};
	}

	//Fiter authenticators
	//Algorithms
	auto to_remove = std::ranges::remove_if(*authenticators, [&options](auto& authenticator) { return !authenticator.chooseAlgoritm(options.allowed_algorithms); });
	if (std::size(to_remove) != 0)
		authenticators->erase(std::begin(to_remove), std::end(to_remove));

	std::vector<Libfido2Authenticator> winhello_authenticators{};
	std::vector<Libfido2Authenticator> standard_authenticators{};
	std::ranges::copy(*authenticators | std::views::filter([](const Libfido2Authenticator& authenticator) {
		return authenticator.winhello(); }), std::back_inserter(winhello_authenticators));
	std::ranges::copy(*authenticators | std::views::filter([](const Libfido2Authenticator& authenticator) {
		return !authenticator.winhello(); }), std::back_inserter(standard_authenticators));

	std::optional<Libfido2Authenticator> authenticator_to_use{};

	if (!standard_authenticators.empty())
	{
		if (standard_authenticators.size() == 1 && !force_always_user_select)
		{
			//Just one authenticator, so select it
			authenticator_to_use = standard_authenticators.front();
		}
		else
		{
			//Give user ability to select device
			authenticator_to_use = getUserSelectedDevice(standard_authenticators);
		}
	}
	else if (!winhello_authenticators.empty())
	{
		//There is no way to ask user which authenticator to use
		authenticator_to_use = winhello_authenticators.front();
	}

	if (!authenticator_to_use)
	{
		user_error_msg = no_good_fido2_devices_err;
		return {};
	}

	return authenticator_to_use;
}


std::optional<webauthn::MakeCredentialResult> webauthn::impl::Webauthnlibfido2::makeCredential(const Libfido2Authenticator& authenticator, const UserData& user, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	std::unique_ptr<fido_dev_t, decltype([](fido_dev_t* ptr)
		{ if (ptr)
			{
				//If device is already closed, nothing will happen
				fido_dev_close(ptr);
				fido_dev_free(&ptr);
			}
		})> device{ fido_dev_new() };

	if (!device)
		return {};

	auto result = fido_dev_open(device.get(), authenticator.getPath().c_str());
	if (result != FIDO_OK)
		return {};

	helpers::fido_cred_ptr credential{ fido_cred_new() };

	//TYPE
	//ONY ACCEPTED: COSE_ES256, COSE_RS256,  COSE_EDDSA
	if (!authenticator.getChosenAlgorithm())
		return {};

	result = fido_cred_set_type(credential.get(), std::to_underlying(*authenticator.getChosenAlgorithm()));
	if (result != FIDO_OK)
		return {};

	//CLIENT DATA
	result = fido_cred_set_clientdata(credential.get(), reinterpret_cast<const unsigned char*>(challange.data()), challange.size());
	if (result != FIDO_OK)
		return {};

	//RELYING PARTY
	//_, id, name
	result = fido_cred_set_rp(credential.get(), rp.ID.c_str(), rp.name.c_str());
	if (result != FIDO_OK)
		return {};

	//USER
	//_, id, id_size, name, display name, icon
	result = fido_cred_set_user(credential.get(), reinterpret_cast<const unsigned char*>(user.ID.data()), user.ID.size(), user.name.c_str(), user.display_name.c_str(), nullptr);
	if (result != FIDO_OK)
		return {};

	result = fido_dev_set_timeout(device.get(), operation_timeout * 1000);
	if (result != FIDO_OK)
		return {};

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

	result = fido_dev_make_cred(device.get(), credential.get(), password ? password->c_str() : nullptr);
	if (result == FIDO_ERR_PIN_INVALID)
	{
		user_error_msg = invalid_pin_err;
		std::cerr << invalid_pin_err << "\n";
	}
	else if (result == FIDO_ERR_PIN_REQUIRED || result == FIDO_ERR_PIN_NOT_SET)
	{
		user_error_msg = no_pin_err;
		std::cerr << no_pin_err << "\n";
	}
	else if (result == FIDO_OK)
	{
		auto attestation_object = helpers::makeAttestationObject(std::move(credential), options.attestation != ATTESTATION::NONE);

		if (!attestation_object)
			return {};

		MakeCredentialResult make_credential_result{};
		make_credential_result.attestation_object = std::move(*attestation_object);
		return make_credential_result;
	}

	return {};
}

std::optional<webauthn::GetAssertionResult> webauthn::impl::Webauthnlibfido2::getAssertion(const Libfido2Authenticator& authenticator, const std::vector<CredentialId>& id, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	std::unique_ptr<fido_dev_t, decltype([](fido_dev_t* ptr)
		{ if (ptr)
			{
				//If device is already closed, nothing will happen
				fido_dev_close(ptr);
				fido_dev_free(&ptr);
			}
		})> device{ fido_dev_new() };

	if (!device)
		return {};

	auto result = fido_dev_open(device.get(), authenticator.getPath().c_str());
	if (result != FIDO_OK)
		return {};

	helpers::fido_assert_ptr assert{ fido_assert_new() };

	//CLIENT DATA
	result = fido_assert_set_clientdata(assert.get(), reinterpret_cast<const unsigned char*>(challange.data()), challange.size());
	if (result != FIDO_OK)
		return {};

	//RELYING PARTY
	//_, id
	result = fido_assert_set_rp(assert.get(), rp.ID.c_str());
	if (result != FIDO_OK)
		return {};

	//ALLOWED CREDENTIALS
	for (auto&& credential : id)
	{
		result = fido_assert_allow_cred(assert.get(), reinterpret_cast<const unsigned char*>(credential.id.data()), credential.id.size());
		if (result != FIDO_OK)
			return {};
	}

	//EXTENSIONS
	//result = fido_assert_set_extensions(assert, ext);
	//if (result != FIDO_OK)
	//	return {};

	//USER PRESENCE
	result = fido_assert_set_up(assert.get(), [&options](){
		/*switch (options.user_pre)
		{
		default:
			break;
		}*/

		return FIDO_OPT_TRUE;
		}());
	if (result != FIDO_OK)
		return {};

	//USER VERIFICATION
	result = fido_assert_set_uv(assert.get(), [&options]() {
		switch (options.user_verification)
		{
		case USER_VERIFICATION::REQUIRED:
			return FIDO_OPT_TRUE;
		case USER_VERIFICATION::DISCOURAGED:
			return FIDO_OPT_FALSE;
		default:
			return FIDO_OPT_OMIT;
		}
		}());
	if (result != FIDO_OK)
		return {};

	result = fido_dev_set_timeout(device.get(), operation_timeout * 1000);
	if (result != FIDO_OK)
		return {};

	result = fido_dev_get_assert(device.get(), assert.get(), password ? password->c_str() : nullptr);
	if (result == FIDO_ERR_PIN_INVALID)
	{
		user_error_msg = invalid_pin_err;
		std::cerr << invalid_pin_err << "\n";
	}
	else if (result == FIDO_ERR_PIN_REQUIRED || result == FIDO_ERR_PIN_NOT_SET)
	{
		user_error_msg = no_pin_err;
		std::cerr << no_pin_err << "\n";
	}
	else if (result == FIDO_OK)
	{
		GetAssertionResult get_assertion_result{};

		//TODO this fido_dev_get_assert can return muliple assertions!!
		//For now return onlu first
		auto x = fido_assert_count(assert.get());
		if (fido_assert_count(assert.get()) > 0)
		{
			result = helpers::unpackCBORByteString(std::span{ fido_assert_authdata_ptr(assert.get(), 0), fido_assert_authdata_len(assert.get(), 0) }).and_then([&get_assertion_result](auto&& data) {
				get_assertion_result.authenticator_data = std::move(data);
				return std::make_optional(true);
				}).value_or(false);
				if (!result)
					return {};

			std::ranges::transform(std::span{ fido_assert_sig_ptr(assert.get(), 0), fido_assert_sig_len(assert.get(), 0) }, std::back_inserter(get_assertion_result.signature),
				[](auto x) { return static_cast<std::byte>(x); });

			if (fido_assert_user_id_len(assert.get(), 0) != 0)
			{
				get_assertion_result.user_id = decltype(get_assertion_result.user_id){};
				std::ranges::transform(std::span{ fido_assert_user_id_ptr(assert.get(), 0), fido_assert_user_id_len(assert.get(), 0) }, std::back_inserter(*(get_assertion_result.user_id)),
					[](auto x) { return static_cast<std::byte>(x); });
			}
			

			return get_assertion_result;
		}
	}

	return {};
}

const std::string webauthn::impl::Webauthnlibfido2::no_fido2_devices_err{ "No FIDO2 authenticator found" };
const std::string webauthn::impl::Webauthnlibfido2::no_good_fido2_devices_err{ "No appropriate FIDO2 authenticator found" };
const std::string webauthn::impl::Webauthnlibfido2::invalid_pin_err{ "Invalid PIN" };
const std::string webauthn::impl::Webauthnlibfido2::no_pin_err{ "Operation requires PIN" };

//libfido2Authenticator

std::optional<webauthn::impl::Libfido2Authenticator> webauthn::impl::Libfido2Authenticator::createLibfido2Authenticator(std::string path, Libfido2Token token)
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

	std::shared_ptr<fido_cbor_info_t> device_info_raw{ fido_cbor_info_new(), [](fido_cbor_info_t* ptr)
		{
			if (ptr) fido_cbor_info_free(&ptr);
		}
	};

	result = fido_dev_get_cbor_info(device.get(), device_info_raw.get());
	if (result != FIDO_OK)
	{
		return {};
	}

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

	
	return { authenticator };
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