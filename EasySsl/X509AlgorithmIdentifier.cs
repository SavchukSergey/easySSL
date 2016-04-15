using Asn1;

namespace EasySsl {
    public class X509AlgorithmIdentifier {

        public X509AlgorithmIdentifier(Asn1ObjectIdentifier algorithmId) {
            Id = algorithmId;
        }

        public X509AlgorithmIdentifier(Asn1Sequence node) {
            var i = 0;
            var subnode = node.Nodes[i++];

            Id = (Asn1ObjectIdentifier)subnode;
            if (node.Nodes.Count > 1) {
                subnode = node.Nodes[i++];
                Parameters = subnode;
            }
        }

        public Asn1ObjectIdentifier Id { get; set; }

        public Asn1Node Parameters { get; set; } = new Asn1Null();

        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    Id,
                    Parameters
                }
            };
        }

        public static X509AlgorithmIdentifier RsaEncryption => new X509AlgorithmIdentifier(Asn1ObjectIdentifier.RsaEncryption);
        public static X509AlgorithmIdentifier Sha256Rsa => new X509AlgorithmIdentifier(new Asn1ObjectIdentifier("1.2.840.113549.1.1.11"));

        public override string ToString() {
            if (Parameters == null || Parameters.Is(Asn1UniversalNodeType.Null)) return $"{Id}";
            return $"{Id}: {Parameters}";
        }

    }
}
