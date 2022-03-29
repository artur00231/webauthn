#include "x509Cert.h"

#include "CryptoExceptions.h"

webauthn::crypto::x509Cert::~x509Cert()
{
    if (bio_mem != nullptr)
    {
        BIO_free(bio_mem);
    }

    if (x509 != nullptr)
    {
        X509_free(x509);
    }
}

webauthn::crypto::x509Cert::x509Cert(x509Cert&& cert) noexcept :
    bio_mem{ cert.bio_mem }, x509{ cert.x509 }
{
    cert.bio_mem = nullptr;
    cert.x509 = nullptr;
}

webauthn::crypto::x509Cert& webauthn::crypto::x509Cert::operator=(x509Cert&& cert) noexcept
{
    this->bio_mem = cert.bio_mem;
    this->x509 = cert.x509;

    cert.bio_mem = nullptr;
    cert.x509 = nullptr;

    return *this;
}

webauthn::crypto::x509Cert webauthn::crypto::x509Cert::loadFromDer(const std::vector<std::byte>& data)
{
    x509Cert cert{};

    cert.bio_mem = BIO_new(BIO_s_mem());
    
    auto writen = BIO_write(cert.bio_mem, reinterpret_cast<const char*>(data.data()), data.size());

    cert.x509 = d2i_X509_bio(cert.bio_mem, nullptr);

    if (cert.x509 == nullptr)
    {
        throw webauthn::crypto::OpenSSLException("OpenSSL error");
    }

    return cert;
}
