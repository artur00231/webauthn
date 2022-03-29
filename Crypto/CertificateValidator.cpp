#include "CertificateValidator.h"

#include <utility>

webauthn::crypto::CertificateValidator::CertificateValidator()
{
	ctx = X509_STORE_CTX_new();
	store = X509_STORE_new();
}

webauthn::crypto::CertificateValidator::CertificateValidator(CertificateValidator&& cv) noexcept :
	ctx{ cv.ctx }, store{ cv.store }
{
	cv.ctx = nullptr;
	cv.store = nullptr;
}

webauthn::crypto::CertificateValidator& webauthn::crypto::CertificateValidator::operator=(CertificateValidator&& cv) noexcept
{
	std::swap(this->ctx, cv.ctx);
	std::swap(this->store, cv.store);

	return *this;
}

webauthn::crypto::CertificateValidator::~CertificateValidator()
{
	if (ctx != nullptr)
	{
		X509_STORE_CTX_free(ctx);
	}

	if (store != nullptr)
	{
		X509_STORE_free(store);
	}
}

webauthn::crypto::CertificateValidator& webauthn::crypto::CertificateValidator::pushCACert(const x509Cert& cert)
{
	X509_STORE_add_cert(store, cert.x509);
	return *this;
}

bool webauthn::crypto::CertificateValidator::verifyCert(const x509Cert& cert)
{
	X509_STORE_CTX_init(ctx, store, cert.x509, nullptr);
	return X509_verify_cert(ctx) == 1;
}
