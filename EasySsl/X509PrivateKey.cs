using System;
using System.Security.Cryptography;
using Asn1;

namespace EasySsl {
    public abstract class X509PrivateKey {

        public abstract X509AlgorithmIdentifier AlgorithmIdentifier { get; }

        public abstract AsymmetricAlgorithm CreateAsymmetricAlgorithm();

        public abstract byte[] SignData(byte[] data);

        protected abstract Asn1Node GetAsn1Arguments();

        public static X509PrivateKey From(Asn1Sequence sequence) {
            var idNode = new X509AlgorithmIdentifier((Asn1Sequence)sequence.Nodes[0]);
            var valueNode = (Asn1BitString)sequence.Nodes[1];
            if (idNode.Id == Asn1ObjectIdentifier.RsaEncryption) {
                return new X509RsaPrivateKey(valueNode);
            }
            throw new NotSupportedException();
        }

        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    new Asn1Integer(0),
                    AlgorithmIdentifier.ToAsn1(),
                    GetAsn1Arguments()
                }
            };
        }

        public string ToPem() {
            var asn1 = ToAsn1();
            var data = asn1.GetBytes();
            var str = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
            str = "-----BEGIN PRIVATE KEY-----\r\n" + str + "\r\n-----END PRIVATE KEY-----";
            return str;
        }

    }
}
