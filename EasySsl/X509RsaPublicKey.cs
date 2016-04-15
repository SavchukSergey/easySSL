using System.Linq;
using System.Security.Cryptography;
using Asn1;

namespace EasySsl {
    public class X509RsaPublicKey : X509PublicKey {

        public X509RsaPublicKey(RSAParameters parameters) {
            Exponent = parameters.Exponent;
            Modulus = parameters.Modulus;
        }

        public X509RsaPublicKey(Asn1BitString valueNode) {
            var value = Asn1Node.ReadNode(valueNode.Data);
            Modulus = GetRsaData((Asn1Integer)value.Nodes[0]);
            Exponent = GetRsaData((Asn1Integer) value.Nodes[1]);
        }

        public byte[] Exponent { get; set; }

        public byte[] Modulus { get; set; }

        public override X509AlgorithmIdentifier AlgorithmIdentifier => new X509AlgorithmIdentifier(Asn1ObjectIdentifier.RsaEncryption);

        public override AsymmetricAlgorithm CreateAsymmetricAlgorithm() {
            var args = ToRsaParameters();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(args);
            return rsa;
        }

        protected override Asn1BitString GetAsn1Arguments() {
            return new Asn1BitString {
                Data = new Asn1Sequence {
                    Nodes = {
                        GetAsn1Integer(Modulus),
                        GetAsn1Integer(Exponent)
                    }
                }.GetBytes()
            };
        }

        public override byte[] GenerateIdentifier() {
            var data = Modulus.Concat(Exponent).ToArray();
            var sha = SHA1.Create();
            var hash = sha.ComputeHash(data);
            hash[0] &= 0x7f;
            return hash;
        }

        public RSAParameters ToRsaParameters() {
            return new RSAParameters {
                Modulus = Modulus,
                Exponent = Exponent
            };
        }

        private static Asn1Integer GetAsn1Integer(byte[] data) {
            if ((data[0] & 0x80) == 0) return new Asn1Integer(data);
            return new Asn1Integer(new byte[] { 0 }.Concat(data).ToArray());
        }

        private static byte[] GetRsaData(Asn1Integer node) {
            if (node.Value.Length == 257) {
                return node.Value.Skip(1).ToArray();
            }
            if (node.Value.Length == 129) {
                return node.Value.Skip(1).ToArray();
            }
            return node.Value;
        }

    }
}
