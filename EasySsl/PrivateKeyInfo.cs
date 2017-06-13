using System;
using System.Text;
using Asn1;

namespace EasySsl {
    public class PrivateKeyInfo {

        public Asn1Integer Version { get; set; } = new Asn1Integer(0);

        public X509AlgorithmIdentifier PrivateKeyAlgorithmIdentifier { get; set; }

        public byte[] PrivateKey { get; set; }

        //https://tools.ietf.org/html/rfc5208#section-5
        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    Version,
                    PrivateKeyAlgorithmIdentifier.ToAsn1(),
                    new Asn1OctetString(PrivateKey)
                }
            };
        }

        public string ToPem() {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            var data = ToAsn1();
            var bytes = data.GetBytes();
            sb.AppendLine(Base64.Convert(bytes));
            sb.AppendLine("-----END PRIVATE KEY-----");
            return sb.ToString();
        }
    }
}
