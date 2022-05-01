#include "pch.h"

#include <CertificateValidator.h>
#include <x509Cert.h>

#include <filesystem>
#include <fstream>

namespace webauthn::crypto
{
	namespace CertificateValidatorTESTHelpers
	{
        const std::filesystem::path TESTRSA{ "test_data/RSA" };
        const std::filesystem::path TESTECDSA{ "test_data/ECDSA" };

		x509Cert loadCert(const std::filesystem::path& path)
		{
            std::fstream in{};
            in.open(path, std::ios::in | std::ios::binary | std::ios::ate);
            if (!in)
            {
                throw std::runtime_error{ "Cannot open file" + path.string() };
            }

            auto size = in.tellg();
            in.seekg(0, std::ios::beg);

            std::vector<std::byte> data(size);
            in.read(reinterpret_cast<char*>(data.data()), size);
            in.close();

            return x509Cert::loadFromDer(data);
		}
	}

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleRSA1)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        
        CertificateValidator CV{};

        CV.pushCACert(CA);

        EXPECT_TRUE(CV.verifyCert(CA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleRSA2)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);

        EXPECT_TRUE(CV.verifyCert(CCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleRSA3)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CCA);

        EXPECT_FALSE(CV.verifyCert(CA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleRSA4)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);

        EXPECT_FALSE(CV.verifyCert(CCCA));
    }

	TEST(CertificateValidatorTEST, CertificateValidatorChainRSA1)
	{
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ccca_cert.der");
        auto CCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CCCA);
        CV.pushCACert(CA);
        CV.pushCACert(CCA);

        EXPECT_TRUE(CV.verifyCert(CCCCA));
	}

    TEST(CertificateValidatorTEST, CertificateValidatorChainRSA2)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ccca_cert.der");
        auto CCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);
        CV.pushCACert(CCA);
        CV.pushCACert(CCCA);

        EXPECT_TRUE(CV.verifyCert(CCCCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorIllegalRSA1)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ccca_cert.der");
        auto CCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cccca_cert.der");
        auto CCCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ccccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);
        CV.pushCACert(CCA);
        CV.pushCACert(CCCA);
        CV.pushCACert(CCCCA);

        EXPECT_FALSE(CV.verifyCert(CCCCCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorIllegalRSA2)
    {
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTRSA / "ccca_cert.der");
        
        CertificateValidator CV{};

        CV.pushCACert(CCA);

        EXPECT_FALSE(CV.verifyCert(CCCA));
    }


    TEST(CertificateValidatorTEST, CertificateValidatorSimpleECDSA1)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);

        EXPECT_TRUE(CV.verifyCert(CA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleECDSA2)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);

        EXPECT_TRUE(CV.verifyCert(CCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleECDSA3)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CCA);

        EXPECT_FALSE(CV.verifyCert(CA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorSimpleECDSA4)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);

        EXPECT_FALSE(CV.verifyCert(CCCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorChainECDSA1)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ccca_cert.der");
        auto CCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CCCA);
        CV.pushCACert(CA);
        CV.pushCACert(CCA);

        EXPECT_TRUE(CV.verifyCert(CCCCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorChainECDSA2)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ccca_cert.der");
        auto CCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);
        CV.pushCACert(CCA);
        CV.pushCACert(CCCA);

        EXPECT_TRUE(CV.verifyCert(CCCCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorIllegalECDSA1)
    {
        auto CA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ca_cert.der");
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ccca_cert.der");
        auto CCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cccca_cert.der");
        auto CCCCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ccccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CA);
        CV.pushCACert(CCA);
        CV.pushCACert(CCCA);
        CV.pushCACert(CCCCA);

        EXPECT_FALSE(CV.verifyCert(CCCCCA));
    }

    TEST(CertificateValidatorTEST, CertificateValidatorIllegalECDSA2)
    {
        auto CCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "cca_cert.der");
        auto CCCA = CertificateValidatorTESTHelpers::loadCert(CertificateValidatorTESTHelpers::TESTECDSA / "ccca_cert.der");

        CertificateValidator CV{};

        CV.pushCACert(CCA);

        EXPECT_FALSE(CV.verifyCert(CCCA));
    }
}