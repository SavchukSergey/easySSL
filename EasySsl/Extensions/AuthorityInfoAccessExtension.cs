using System;
using System.Collections.Generic;
using Asn1;
using System.Text;

namespace EasySsl.Extensions {
    public class AuthorityInfoAccessExtension : X509Extension {

        public override Asn1ObjectIdentifier Id => Asn1ObjectIdentifier.AuthorityInfoAccess;

        public IList<AuthorityAccessDescription> Methods { get; } = new List<AuthorityAccessDescription>();

        public AuthorityInfoAccessExtension() {
        }

        public AuthorityInfoAccessExtension(byte[] data) {
            var seq = Asn1Sequence.ReadNode(data);
            foreach (var node in seq.Nodes) {
                var mn = (Asn1Sequence)node;
                var id = (Asn1ObjectIdentifier)mn.Nodes[0];
                var cd = (Asn1CustomNode)mn.Nodes[1];
                var str = Encoding.UTF8.GetString(cd.Data);
                Methods.Add(new AuthorityAccessDescription {
                    Url = str
                });
            }

        }
        protected override byte[] GetBytesCore() {
            var seq = new Asn1Sequence();

            foreach (var method in Methods) {
                seq.Nodes.Add(new Asn1Sequence {
                    Nodes = {
                        new Asn1ObjectIdentifier("1.3.6.1.5.5.7.48.2"),
                        new Asn1CustomNode(0x06, Asn1TagForm.Primitive, Asn1TagClass.ContextDefined) {
                            Data = Encoding.UTF8.GetBytes(method.Url)
                        }
                    }
                });
            }

            return seq.GetBytes();
        }

    }
}
