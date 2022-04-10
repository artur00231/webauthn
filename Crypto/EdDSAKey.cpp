#include "EdDSAKey.h"

#include <memory>

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <iostream>

std::optional<webauthn::crypto::EdDSAKey> webauthn::crypto::EdDSAKey::create(const std::vector<std::byte>& bin_x, const COSE::EdDSA_EC ec)
{
    EdDSAKey EdDSA_key{};

    switch (ec)
    {
    case COSE::EdDSA_EC::Ed25519:
        EdDSA_key.pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(bin_x.data()), bin_x.size());
        break;
    case COSE::EdDSA_EC::Ed448:
        EdDSA_key.pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED448, nullptr, reinterpret_cast<const unsigned char*>(bin_x.data()), bin_x.size());
        break;
    default:
        return {};
    }

    if (EdDSA_key.pkey == nullptr)
    {
        return {};
    }

    return EdDSA_key;
}

std::optional<bool> webauthn::crypto::EdDSAKey::verify(const std::string& data, const std::string& signature, const COSE::SIGNATURE_HASH hash) const
{
    return verify(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), hash);
}

std::optional<bool> webauthn::crypto::EdDSAKey::verify(const std::vector<std::byte>& data, const std::vector<std::byte>& signature, const COSE::SIGNATURE_HASH hash) const
{
    return verify(reinterpret_cast<const unsigned char*>(data.data()), data.size(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), hash);
}

std::optional<bool> webauthn::crypto::EdDSAKey::verify(const unsigned char* data, std::size_t data_size, const unsigned char* signature, std::size_t signature_size, const COSE::SIGNATURE_HASH hash) const
{
    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* ptr) {
        if (ptr) EVP_MD_CTX_free(ptr);})>mdctx{ EVP_MD_CTX_new() };

    if (!mdctx) return {};

    auto result = EVP_DigestVerifyInit(mdctx.get(), NULL, NULL, NULL, pkey);
    if (result != 1) 
    {
        return {};
    }

    result = EVP_DigestVerify(mdctx.get(), signature, signature_size, data, data_size);
    if (result == 1) 
    {
        return true;
    }

    if (result == 0)
    {
        return false;
    }

    return {};
}

webauthn::crypto::EdDSAKey::EdDSAKey(EdDSAKey&& key) noexcept : pkey{ key.pkey }, default_hash{ key.default_hash }
{
    key.pkey = nullptr;
}

webauthn::crypto::EdDSAKey& webauthn::crypto::EdDSAKey::operator=(EdDSAKey&& key) noexcept
{
    pkey = key.pkey;
    key.pkey = nullptr;

    default_hash = key.default_hash;

    return *this;
}

webauthn::crypto::EdDSAKey::~EdDSAKey()
{
    EVP_PKEY_free(pkey);
}
