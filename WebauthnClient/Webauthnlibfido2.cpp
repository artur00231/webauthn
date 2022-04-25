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

	//TODO clean it!!!!!!!!!!!
	std::optional<std::vector<std::byte>> makeAttestationObject(Libfido2Authenticator::MakeCredentialLibfido2Result&& credential, bool include_attestation)
	{
		static constexpr std::size_t AAGUID_offset = 37;
		static constexpr std::size_t AAGUID_size = 16;

		static constexpr std::size_t max_return_vector_size = /*2^*/28; //~268.4MB

		using namespace std::string_literals;
		if (credential.format.empty())
			return {};

		if (!include_attestation)
		{
			credential.format = "none";
		}

		auto authenticator_data = AuthenticatorData::fromBin(credential.authenticator_data);

		//If format == none then
		//Remove attstmt
		//Replace AAGUID with zeros
		if (credential.format == "none"s)
		{
			//Replace AAGUID with zeros
			if (authenticator_data.attested_credential_data)
			{
				std::ranges::for_each(authenticator_data.attested_credential_data->AAGUID, [](std::byte& byte) { byte = std::byte{ 0 }; });
			}

			credential.attestation_statement.clear();
		}

		credential.authenticator_data = authenticator_data.toBin();

		//Create AttestationObject
		//MAP 3
		// fmt
		// attStmt 
		// authData
		CBOR::CBORHandle handle{ CBOR::cbor_new_definite_map(3) };
		CBOR::cbor_map_add(handle,
			CBOR::cbor_pair{
				.key = CBOR::cbor_move(CBOR::cbor_build_string("fmt")),
				.value = CBOR::cbor_move(CBOR::cbor_build_string(credential.format.c_str()))
		});
		if (credential.attestation_statement.empty())
		{
			CBOR::cbor_map_add(handle,
				CBOR::cbor_pair{
					.key = CBOR::cbor_move(CBOR::cbor_build_string("attStmt")),
					.value = CBOR::cbor_move(CBOR::cbor_new_definite_map(0))
				});
		}
		else
		{
			auto [attStmt_handle, load_result] = CBOR::CBORHandle::fromBin(credential.attestation_statement);
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
				.value = CBOR::cbor_move(CBOR::cbor_build_bytestring(reinterpret_cast<const unsigned char*>(credential.authenticator_data.data()), credential.authenticator_data.size()))
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
	auto credential = authenticator_to_use->makeCredential(Libfido2Token{}, user, rp, challange, password, options);

	if (credential.success == FIDO_ERR_PIN_INVALID)
	{
		user_error_msg = invalid_pin_err;
		std::cerr << invalid_pin_err << "\n";
	}
	else if (credential.success == FIDO_ERR_PIN_REQUIRED || credential.success == FIDO_ERR_PIN_NOT_SET)
	{
		user_error_msg = no_pin_err;
		std::cerr << no_pin_err << "\n";
	}
	else if (credential.success == FIDO_OK)
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

std::optional<webauthn::GetAssertionResult> webauthn::impl::Webauthnlibfido2::getAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp, const std::vector<std::byte>& challange, const std::optional<std::string>& password, const WebAuthnOptions& options)
{
	//Start library
	fido_init(FIDO_DISABLE_U2F_FALLBACK);

	std::optional<Libfido2Authenticator> authenticator_to_use{};

	if (auto_authenticator_get_assert)
		authenticator_to_use = getSuitableDeviceForAssertion(id, rp, options);

	if (!authenticator_to_use)
		authenticator_to_use = getSuitableDevice(options);

	//Make credential using libfido2
	auto assertion = authenticator_to_use->getAssertion(Libfido2Token{}, id, rp, challange, password, options);

	if (assertion.success == FIDO_ERR_PIN_INVALID)
	{
		user_error_msg = invalid_pin_err;
		std::cerr << invalid_pin_err << "\n";
	}
	else if (assertion.success == FIDO_ERR_PIN_REQUIRED || assertion.success == FIDO_ERR_PIN_NOT_SET)
	{
		user_error_msg = no_pin_err;
		std::cerr << no_pin_err << "\n";
	}
	else if (assertion.success == FIDO_OK)
	{
		GetAssertionResult get_assertion_result{};
		
		//TODO change it
		//Form now just get first assertion
		if (!assertion.assert_datas.empty())
		{
			get_assertion_result.user_id = std::move(assertion.assert_datas.front().user_id);
			get_assertion_result.signature = std::move(assertion.assert_datas.front().signature);

			if (auto success = helpers::unpackCBORByteString(assertion.assert_datas.front().cbor_authdata).and_then([&get_assertion_result](std::vector<std::byte>&& auth_data) {
				get_assertion_result.authenticator_data = std::move(auth_data);
				return std::make_optional(true);
				}).value_or(false);
					!success)
				return {};

			return get_assertion_result;
		}
		else
		{
			return {};
		}
	}

	return {};
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
		return {};

	if (authenticators->empty())
	{
		user_error_msg = no_fido2_devices_err;
		return {};
	}

	//Fiter authenticators
	authenticators = filterAuthenticators(*authenticators, options);

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

std::optional<webauthn::impl::Libfido2Authenticator> webauthn::impl::Webauthnlibfido2::getSuitableDeviceForAssertion(const std::vector<CredentialId>& id, const RelyingParty& rp, WebAuthnOptions options)
{
	//Search for appropriate FIDO2 authenticator 
	auto authenticators = getAvaiableFidoDevices();
	if (!authenticators)
		return {};

	//Fiter authenticators
	authenticators = filterAuthenticators(*authenticators, options);
	if (authenticators->empty())
		return {};

	std::vector<std::byte> challenge(32, std::byte{ 0 });
	options.user_presence = USER_PRESENCE::DISCOURAGED;
	options.user_verification = USER_VERIFICATION::PREFERRED;
	options.timeout = 100;

	std::optional<Libfido2Authenticator> authenticator_to_use{};

	for (Libfido2Authenticator& authenticator : *authenticators)
	{
		auto assertion = authenticator.getAssertion(Libfido2Token{}, id, rp, challenge, {}, options);

		if (assertion.success == FIDO_ERR_PIN_REQUIRED || assertion.success == FIDO_OK)
		{
			authenticator_to_use = authenticator;
		}
	}

	return authenticator_to_use;
}

std::vector<webauthn::impl::Libfido2Authenticator> webauthn::impl::Webauthnlibfido2::filterAuthenticators(std::vector<Libfido2Authenticator> authenticators, const WebAuthnOptions& options)
{
	//Algorithms
	auto to_remove = std::ranges::remove_if(authenticators, [&options](auto& authenticator) { return !authenticator.chooseAlgoritm(options.allowed_algorithms); });
	if (std::size(to_remove) != 0)
		authenticators.erase(std::begin(to_remove), std::end(to_remove));
	
	return authenticators;
}

const std::string webauthn::impl::Webauthnlibfido2::no_fido2_devices_err{ "No FIDO2 authenticator found" };
const std::string webauthn::impl::Webauthnlibfido2::no_good_fido2_devices_err{ "No appropriate FIDO2 authenticator found" };
const std::string webauthn::impl::Webauthnlibfido2::invalid_pin_err{ "Invalid PIN" };
const std::string webauthn::impl::Webauthnlibfido2::no_pin_err{ "Operation requires PIN" };