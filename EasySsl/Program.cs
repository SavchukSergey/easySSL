using System;
using EasySsl.Extensions;

namespace EasySsl {
    class Program {
        private static X509Certificate ca;

        private static X509Certificate GenerateCaCertificate() {
            var cert = new X509Certificate {
                Tbs = {
                    SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
                    Issuer = new X509Name {
                        CommonName = "Sergey CA",
                        Organization = "My Ca"
                    },
                    Validity = new X509Validity {
                        NotBefore = DateTimeOffset.UtcNow,
                        NotAfter = DateTimeOffset.UtcNow.AddDays(5)
                    },
                    Subject = new X509Name {
                        CommonName = "Sergey CA",
                        Organization = "My Ca"
                    }
                },
                SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa
            }
            .GenerateRsaKey()
            .GenerateSerialNumber()
            .SetBasicConstraint(new BasicConstraintData {
                Authority = true,
                PathLengthConstraint = 3
            })
            .SignSelf();

            return cert;
        }

        private static X509Certificate GenerateEndCertificate() {
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
                },
                SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa
            }
            .SetIssuer(ca)
            .GenerateRsaKey()
            .GenerateSerialNumber()
            .AddSubjectAltNames("test2.vcap.me")
            .SignWith(ca);

            return cert;
        }

        static void Main() {
            ca = GenerateCaCertificate();
            ca.Export(@"d:\temp\ca.cer", true);

            var end = GenerateEndCertificate();
            end.Export(@"d:\temp\end.cer", true);

            Console.WriteLine("certs generated");
            Console.ReadKey();
        }

    }
}
