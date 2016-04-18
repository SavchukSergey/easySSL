using System.Linq;
using System.Security.Cryptography;
using Asn1;

namespace EasySsl {
    //https://www.ietf.org/rfc/rfc2313.txt

    public class X509RsaPrivateKey : X509PrivateKey {

        public X509RsaPrivateKey(RSAParameters parameters) {
            Exponent = parameters.Exponent;
            Modulus = parameters.Modulus;
            D = parameters.D;
            P = parameters.P;
            Q = parameters.Q;
            DP = parameters.DP;
            DQ = parameters.DQ;
            InverseQ = parameters.InverseQ;
        }

        public X509RsaPrivateKey(Asn1BitString valueNode) {
            var value = Asn1Node.ReadNode(valueNode.Data);
            Modulus = GetRsaData((Asn1Integer)value.Nodes[1]);
            Exponent = GetRsaData((Asn1Integer)value.Nodes[2]);
            D = GetRsaData((Asn1Integer)value.Nodes[3]);
            P = GetRsaData((Asn1Integer)value.Nodes[4]);
            Q = GetRsaData((Asn1Integer)value.Nodes[5]);
            DP = GetRsaData((Asn1Integer)value.Nodes[6]);
            DQ = GetRsaData((Asn1Integer)value.Nodes[7]);
            InverseQ = GetRsaData((Asn1Integer)value.Nodes[8]);
        }

        public X509RsaPrivateKey(int keySize) : this(new RSACryptoServiceProvider(keySize).ExportParameters(true)) {
        }

        public X509RsaPrivateKey() {

        }

        public byte[] Exponent { get; set; }

        public byte[] Modulus { get; set; }

        public byte[] D { get; set; }

        public byte[] P { get; set; }

        public byte[] Q { get; set; }

        public byte[] DP { get; set; }

        public byte[] DQ { get; set; }

        public byte[] InverseQ { get; set; }

        public override X509AlgorithmIdentifier AlgorithmIdentifier => new X509AlgorithmIdentifier(Asn1ObjectIdentifier.RsaEncryption);

        public override AsymmetricAlgorithm CreateAsymmetricAlgorithm() {
            var args = ToRsaParameters();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(args);
            return rsa;
        }

        public override byte[] SignData(byte[] data) {
            var args = ToRsaParameters();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(args);
            var res = rsa.SignData(data, SHA256.Create());
            return res;
        }

        protected override Asn1Node GetAsn1Arguments() {
            return new Asn1OctetString {
                Data = new Asn1Sequence {
                    Nodes = {
                        new Asn1Integer(0),
                        GetAsn1Integer(Modulus),
                        GetAsn1Integer(Exponent),
                        GetAsn1Integer(D),
                        GetAsn1Integer(P),
                        GetAsn1Integer(Q),
                        GetAsn1Integer(DP),
                        GetAsn1Integer(DQ),
                        GetAsn1Integer(InverseQ),
                    }
                }.GetBytes()
            };
        }

        public RSAParameters ToRsaParameters() {
            return new RSAParameters {
                Modulus = Modulus,
                Exponent = Exponent,
                D = D,
                P = P,
                Q = Q,
                DP = DP,
                DQ = DQ,
                InverseQ = InverseQ
            };
        }

        public X509RsaPublicKey CreatePublicKey() {
            return new X509RsaPublicKey(ToRsaParameters());
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
