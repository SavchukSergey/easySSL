using System;
using System.Text;
using Asn1;

namespace EasySsl {
    public class SubjectPublicKeyInfo {

        public X509AlgorithmIdentifier Algorithm { get; set; }

        public byte[] SubjectPublicKey { get; set; }

        public X509PublicKey CreatePublicKey() {
            if (Algorithm.Id == Asn1ObjectIdentifier.RsaEncryption) {
                return new RsaPublicKey(new Asn1BitString(SubjectPublicKey));
            }

            throw new NotSupportedException();
        }

        public static SubjectPublicKeyInfo From(Asn1Sequence sequence) {
            var idNode = new X509AlgorithmIdentifier((Asn1Sequence)sequence.Nodes[0]);
            var valueNode = (Asn1BitString)sequence.Nodes[1];
            return new SubjectPublicKeyInfo {
                Algorithm = idNode,
                SubjectPublicKey = valueNode.Data
            };
        }

        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    Algorithm.ToAsn1(),
                    new Asn1BitString(SubjectPublicKey)
                }
            };
        }

        public string ToPem() {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PUBLIC KEY-----");
            var data = ToAsn1();
            var bytes = data.GetBytes();
            sb.AppendLine(Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END PUBLIC KEY-----");
            return sb.ToString();
        }
    }
}
