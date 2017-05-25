using System;
using System.IO;
using Asn1.Utils;
using EasySsl.Extensions;

namespace EasySsl {
    class Program {
        private static X509Certificate GenerateCaCertificate() {
            return new X509Certificate {
                Tbs = {
                    SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
                    Validity = new X509Validity {
                        NotBefore = DateTimeOffset.UtcNow,
                        NotAfter = DateTimeOffset.UtcNow.AddDays(5)
                    },
                    Subject = new X509Name {
                        CommonName = "Root CA",
                        Organization = "EasySSL"
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
        }

        private static X509Certificate GenerateIntermediateCertificate(X509Certificate root) {
            var intermediatePrivateKey = new RsaPrivateKey(2048);
            var csr = new CertificationRequestInfo {
                Subject = new X509Name {
                    CommonName = "Intermediate CA",
                    Organization = "EasySSL"
                },
                SubjectPublicKeyInfo = intermediatePrivateKey.CreatePublicKey().GetSubjectPublicKeyInfo()
            }.SetBasicConstraint(new BasicConstraintData {
                Authority = true,
                PathLengthConstraint = 2
            }).SetAuthorityInfoAccess(new AuthorityInfoAccess {
                Methods = {
                    new AuthorityAccessDescription { Url = "http://ssl.vcap.me/ca.crt"}
                }
            });

            return Sign(csr, root).SetPrivateKey(intermediatePrivateKey);
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
                        CommonName = "vcap.me",
                        Organization = "Home"
                    }
                }
            }
            .SetIssuer(ca)
            .GenerateRsaKey()
            .GenerateSerialNumber()
            .AddSubjectAltNames("vcap.me", "*.vcap.me")
            .SetAuthorityInfoAccess(new AuthorityInfoAccess {
                Methods = {
                    new AuthorityAccessDescription { Url = "http://ssl.vcap.me/intermediate.crt"}
                }
            })
            .SignWith(ca);

            return cert;
        }



        private static X509Certificate Sign(CertificationRequestInfo csr, X509Certificate authority) {
            return new X509Certificate {
                Tbs = {
                    SignatureAlgorithm = X509AlgorithmIdentifier.Sha256Rsa,
                    Validity = new X509Validity {
                        NotBefore = DateTimeOffset.UtcNow,
                        NotAfter = DateTimeOffset.UtcNow.AddDays(5)
                    },
                    Subject = csr.Subject,
                    SubjectPublicKeyInfo = csr.SubjectPublicKeyInfo
                },
            }.AddExtensions(csr.RequestedExtensions).SetIssuer(authority).GenerateSerialNumber().SetSubjectKeyIdentifier(csr.SubjectPublicKeyInfo.GenerateIdentifier()).SignWith(authority);

        }

        public static void Main() {
            var root = GenerateCaCertificate().Export("ca.crt").ExportPrivateKey("ca.key");
            Console.WriteLine($"Root authority has been generated\r\n{Utils.StringUtils.GetHexString(root.SignatureValue)}");

            var intermediateCertificate = GenerateIntermediateCertificate(root).Export("intermediate.crt");
            Console.WriteLine($"Intermediate authority has been generated\r\n{Utils.StringUtils.GetHexString(intermediateCertificate.SignatureValue)}");

            var endCertificate = GenerateEndCertificate(intermediateCertificate).Export("vcap.me.crt");
            Console.WriteLine($"End certificate has been generated\r\n{Utils.StringUtils.GetHexString(endCertificate.SignatureValue)}");
            Console.ReadKey();


            var inputBuffer = new byte[1024];
            var inputStream = Console.OpenStandardInput(inputBuffer.Length);
            Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));

            var key = new RsaPrivateKey(2048);
            var publicKey = key.CreatePublicKey();
            var pem = publicKey.GetSubjectPublicKeyInfo().ToPem();
            Console.WriteLine(pem);
            Console.ReadKey();

            var privatePem = key.GetPrivateKeyInfo().ToPem();
            Console.WriteLine(privatePem);
            Console.ReadKey();

            //for (var i = 0; i < 3; i++) {
            //    var line1 = Console.ReadLine();
            //    var data1 = Encoding.UTF8.GetBytes(line1);
            //    var signature = key.SignData(data1);
            //    Console.WriteLine(signature.GetHexString());
            //}
            //Console.ReadKey();


            //var pvk = PrivateKeyFile.Read(@"test.pvk");
            //var blob = RsaPrivateKeyBlob.Read(pvk.Key);
            //var para = blob.ToRsaParamaters();
            //var rsa = new RsaPrivateKey(para);
            //var signature = rsa.SignData(Encoding.UTF8.GetBytes("test"));




            var ca = GenerateCaCertificate();
            ca.Export(@"d:\temp\ca.pfx", false);
            ca.ExportPvk(@"d:\temp\ca.pvk");

            var end = GenerateEndCertificate(ca);
            end.Export(@"d:\temp\end.pfx", false);

            Console.WriteLine("certs generated");
            Console.ReadKey();
        }

    }
}
