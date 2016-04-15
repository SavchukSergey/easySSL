using System;
using System.Security.Cryptography;
using Asn1;

namespace EasySsl {
    public abstract class X509PublicKey {

        public abstract X509AlgorithmIdentifier AlgorithmIdentifier { get; }

        public abstract AsymmetricAlgorithm CreateAsymmetricAlgorithm();

        protected abstract Asn1BitString GetAsn1Arguments();

        public abstract byte[] GenerateIdentifier();

        public static X509PublicKey From(Asn1Sequence sequence) {
            var idNode = new X509AlgorithmIdentifier((Asn1Sequence)sequence.Nodes[0]);
            var valueNode = (Asn1BitString)sequence.Nodes[1];
            if (idNode.Id == Asn1ObjectIdentifier.RsaEncryption) {
                return new X509RsaPublicKey(valueNode);
            }
            throw new NotSupportedException();
        }

        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    AlgorithmIdentifier.ToAsn1(),
                    GetAsn1Arguments()
                }
            };
        }
    }
}
