using System;
using EasySsl.Extensions;

namespace EasySsl {
    class Program {
        private static X509Certificate GenerateCaCertificate() {
            var cert = new X509Certificate {
                Tbs = {
                    SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
                    Validity = new X509Validity {
                        NotBefore = DateTimeOffset.UtcNow,
                        NotAfter = DateTimeOffset.UtcNow.AddDays(5)
                    },
                    Subject = new X509Name {
                        CommonName = "Sergey CA",
                        Organization = "My Ca"
                    }
                }
            }
            .GenerateRsaKey()
            .GenerateSerialNumber()
            .SetIssuerSelf()
            .SetBasicConstraint(new BasicConstraintData {
                Authority = true,
                PathLengthConstraint = 3
            })
            .SignSelf();

            return cert;
        }

        private static X509Certificate GenerateEndCertificate(X509Certificate ca) {
            var cert = new X509Certificate {
                Tbs = {
                    SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
                    Validity = new X509Validity {
                        NotBefore = DateTimeOffset.UtcNow,
                        NotAfter = DateTimeOffset.UtcNow.AddDays(5)
                    },
                    Subject = new X509Name {
                        CommonName = "test.vcap.me",
                        Organization = "Home"
                    }
                }
            }
            .SetIssuer(ca)
            .GenerateRsaKey()
            .GenerateSerialNumber()
            .AddSubjectAltNames("test2.vcap.me")
            .SignWith(ca);

            return cert;
        }

        static void Main() {
            var ca = GenerateCaCertificate();
            ca.Export(@"d:\temp\ca.pfx", true);

            var end = GenerateEndCertificate(ca);
            end.Export(@"d:\temp\end.pfx", true);

            Console.WriteLine("certs generated");
            Console.ReadKey();
        }

    }
}
