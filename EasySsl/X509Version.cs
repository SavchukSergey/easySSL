using Asn1;

namespace EasySsl {
    public class X509Version {

        public X509Version(Asn1Node subnode) {
            Value = (Asn1Integer)subnode.Nodes[0];
        }

        public X509Version(int version) {
            Value = new Asn1Integer(version - 1);
        }

        public Asn1Integer Value { get; set; }

        public Asn1Node ToAsn1() {
            return new Asn1CustomNode(0, Asn1TagForm.Constructed, Asn1TagClass.ContextDefined) {
                Nodes = {
                    Value
                }
            };
        }

    }
}
