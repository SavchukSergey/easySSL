using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Asn1;
using EasySsl.Extensions;

namespace EasySsl {
    public class X509Certificate {

        public X509Certificate() {
            Tbs = new X509TbsCertificate();
        }

        //https://tools.ietf.org/html/rfc5280#section-4.1
        public X509Certificate(Asn1Sequence node) {
            var i = 0;
            var subnode = node.Nodes[i++];

            Tbs = new X509TbsCertificate((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            SignatureAlgorithm = new X509AlgorithmIdentifier((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            SignatureValue = (Asn1BitString)subnode;
        }


        public X509TbsCertificate Tbs { get; set; }

        public X509AlgorithmIdentifier SignatureAlgorithm { get; set; }

        public Asn1BitString SignatureValue { get; set; }

        public X509PrivateKey PrivateKey { get; set; }

        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    Tbs.ToAsn1(),
                    SignatureAlgorithm.ToAsn1(),
                    SignatureValue
                }
            };
        }

        public X509Certificate AddSubjectAltNames(params string[] names) {
            var ext = Tbs.Extensions.FirstOrDefault(e => e.Id == Asn1ObjectIdentifier.SubjectAltName);
            if (ext == null) {
                ext = new X509Extension {
                    Id = Asn1ObjectIdentifier.SubjectAltName
                };
                Tbs.Extensions.Add(ext);
            }
            var val = ext.Value;
            var node = val != null && val.Length != 0 ? Asn1Sequence.ReadFrom(val) : new Asn1Sequence();

            foreach (var name in names) {
                node.Nodes.Add(new Asn1CustomNode(2, Asn1TagForm.Primitive, Asn1TagClass.ContextDefined) {
                    Data = Encoding.UTF8.GetBytes(name)
                });
            }

            ext.Value = node.GetBytes();
            return this;
        }

        public X509Certificate GenerateRsaKey(int keySize = 2048) {
            var privateKey = new X509RsaPrivateKey(2048);
            var publicKey = privateKey.CreatePublicKey();
            Tbs.PublicKey = publicKey;
            PrivateKey = privateKey;
            Tbs.Extensions.SetSubjectKeyIdentifier(publicKey.GenerateIdentifier());
            return this;
        }

        public X509Certificate GenerateSerialNumber() {
            using (var rnd = new RNGCryptoServiceProvider()) {
                var res = new byte[20];
                rnd.GetBytes(res);
                res[0] &= 0x7f;
                Tbs.SerialNumber = new Asn1Integer(res);
                return this;
            }
        }

        public X509Certificate SignWith(X509Certificate authority) {
            Tbs.Extensions.SetAuthorityKeyIdentifier(authority.Tbs.Extensions.GetSubjectKeyIdentifier());
            SignWith(authority.PrivateKey);
            return this;
        }

        public X509Certificate SignSelf() {
            return SignWith(this);
        }

        public X509Certificate SignWith(X509PrivateKey authorityPrivateKey) {
            var tbsData = Tbs.ToAsn1().GetBytes();
            var data = authorityPrivateKey.SignData(tbsData);
            SignatureValue = new Asn1BitString(data);
            SignatureAlgorithm = Tbs.SignatureAlgorithm;
            return this;
        }

        public X509Certificate SetIssuer(X509Certificate authority) {
            Tbs.Issuer = authority.Tbs.Subject;
            var id = authority.Tbs.Extensions.GetSubjectKeyIdentifier();
            Tbs.Extensions.SetAuthorityKeyIdentifier(id);
            return this;
        }

        public X509Certificate SetBasicConstraint(BasicConstraintData data) {
            var seq = new Asn1Sequence { Nodes = { new Asn1Boolean(data.Authority) } };
            if (data.PathLengthConstraint.HasValue) {
                seq.Nodes.Add(new Asn1Integer(data.PathLengthConstraint.Value));
            }
            Tbs.Extensions.Add(new X509Extension {
                Id = Asn1ObjectIdentifier.BasicConstraints,
                Critical = true,
                Value = seq.GetBytes()
            });

            return this;
        }

        public string ToPem() {
            var asn1 = ToAsn1();
            var data = asn1.GetBytes();
            var str = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
            str = "-----BEGIN CERTIFICATE-----\r\n" + str + "\r\n-----END CERTIFICATE-----";
            return str;
        }

        public void Export(string filePath, bool includePrivate = false) {
            using (var writer = new StreamWriter(filePath)) {
                var pem = ToPem();
                writer.Write(pem);

                if (PrivateKey != null && includePrivate) {
                    writer.WriteLine();
                    writer.WriteLine();
                    writer.Write(PrivateKey.ToPem());
                }

                writer.Flush();
            }
        }

    }
}
