using System;
using System.IO;
using System.Text;
using Asn1.Utils;
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

        public static void Main() {
            var inputBuffer = new byte[1024];
            var inputStream = Console.OpenStandardInput(inputBuffer.Length);
            Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));

            //var key = new RsaPrivateKey(2048);
            //var publicKey = key.CreatePublicKey();
            //var pem = publicKey.GetSubjectPublicKeyInfo().ToPem();
            //Console.WriteLine(pem);
            //Console.ReadKey();

            //var privatePem = key.GetPrivateKeyInfo().ToPem();
            //Console.WriteLine(privatePem);
            //Console.ReadKey();

            //for (var i = 0; i < 3; i++) {
            //    var line1 = Console.ReadLine();
            //    var data1 = Encoding.UTF8.GetBytes(line1);
            //    var signature = key.SignData(data1);
            //    Console.WriteLine(signature.GetHexString());
            //}
            //Console.ReadKey();



            var ca = GenerateCaCertificate();
            ca.Export(@"d:\temp\ca.pfx", false);

            var end = GenerateEndCertificate(ca);
            end.Export(@"d:\temp\end.pfx", false);

            Console.WriteLine("certs generated");
            Console.ReadKey();
        }

    }
}
