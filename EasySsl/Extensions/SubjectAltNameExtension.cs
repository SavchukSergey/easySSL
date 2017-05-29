using Asn1;
using System.Collections.Generic;
using System.Text;

namespace EasySsl.Extensions {
    public class SubjectAltNameExtension : X509Extension {

        public override Asn1ObjectIdentifier Id => Asn1ObjectIdentifier.SubjectAltName;

        public IList<string> Names { get; } = new List<string>();

        protected override byte[] GetBytesCore() {
            var node = new Asn1Sequence();

            foreach (var name in Names) {
                node.Nodes.Add(new Asn1CustomNode(2, Asn1TagForm.Primitive, Asn1TagClass.ContextDefined) {
                    Data = Encoding.UTF8.GetBytes(name)
                });
            }

            return node.GetBytes();
        }

    }
}
