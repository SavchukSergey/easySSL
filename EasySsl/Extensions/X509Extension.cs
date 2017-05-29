using Asn1;
using EasySsl.Utils;

namespace EasySsl.Extensions {
    public abstract class X509Extension {

        public abstract Asn1ObjectIdentifier Id { get; }

        public bool Critical { get; set; }

        protected X509Extension() {
        }

        public static X509Extension From(Asn1Sequence node) {
            var i = 0;
            var subnode = node.Nodes[i++];

            var id = (Asn1ObjectIdentifier)subnode;
            subnode = node.Nodes[i++];

            var critical = false;

            if (subnode.Is(Asn1UniversalNodeType.Boolean)) {
                critical = ((Asn1Boolean)subnode).Value;
                subnode = node.Nodes[i++];
            }

            var value = ((Asn1OctetString)subnode).Data;

            var ext = FromCore(id, value);
            ext.Critical = critical;

            return ext;
        }

        private static X509Extension FromCore(Asn1ObjectIdentifier id, byte[] data) {
            if (id == Asn1ObjectIdentifier.BasicConstraints) {
                return BasicConstraintExtension.FromExtensionData(data);
            } else if (id == Asn1ObjectIdentifier.AuthorityKeyIdentifier) {
                return AuthorityKeyIdentifierExtension.FromExtensionData(data);
            }
            return new UnknownExtension(id, data);
        }

        protected abstract byte[] GetBytesCore();

        public override string ToString() {
            return $"{Id}: {GetBytesCore().GetHexString()}";
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

            res.Nodes.Add(new Asn1OctetString(GetBytesCore()));

            return res;
        }
    }
}
