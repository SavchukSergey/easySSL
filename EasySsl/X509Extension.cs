using Asn1;
using EasySsl.Utils;

namespace EasySsl {
    public class X509Extension {

        public Asn1ObjectIdentifier Id { get; set; }

        public bool Critical { get; set; }

        public byte[] Value { get; set; }

        public X509Extension() {

        }

        public X509Extension(Asn1Sequence node) {
            var i = 0;
            var subnode = node.Nodes[i++];

            Id = (Asn1ObjectIdentifier)subnode;
            subnode = node.Nodes[i++];

            if (subnode.Is(Asn1UniversalNodeType.Boolean)) {
                Critical = ((Asn1Boolean)subnode).Value;
                subnode = node.Nodes[i++];
            }

            Value = ((Asn1OctetString)subnode).Data;
        }

        public override string ToString() {
            return $"{Id}: {Value.GetHexString()}";
        }

        public Asn1Node ToAsn1() {
            var res = new Asn1Sequence {
                Nodes = {
                    Id
                }
            };

            if (Critical) {
                res.Nodes.Add(new Asn1Boolean(Critical));
            }

            res.Nodes.Add(new Asn1OctetString(Value));

            return res;
        }
    }
}
