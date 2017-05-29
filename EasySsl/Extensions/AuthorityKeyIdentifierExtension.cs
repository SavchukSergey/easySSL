using Asn1;

namespace EasySsl.Extensions {
    public class AuthorityKeyIdentifierExtension : X509Extension {

        public override Asn1ObjectIdentifier Id => Asn1ObjectIdentifier.AuthorityKeyIdentifier;

        public byte[] IssuerKeyIdentifier { get; set; }

        public AuthorityKeyIdentifierExtension() {
        }

        public AuthorityKeyIdentifierExtension(byte[] id) {
            IssuerKeyIdentifier = id;
        }

        protected override byte[] GetBytesCore() {
            return new Asn1Sequence {
                Nodes = {
                        new Asn1CustomNode(0x00, Asn1TagForm.Primitive, Asn1TagClass.ContextDefined) {
                            Data = IssuerKeyIdentifier
                        }//,
                        //new Asn1CustomNode(0x01, Asn1TagForm.Primitive) {
                        //    TagClass = Asn1TagClass.ContextDefined,
                        //    Data = new Asn1Utf8String(Subject.CommonName).GetBytes()
                        //},
                        //new Asn1CustomNode(0x02, Asn1TagForm.Primitive) {
                        //    TagClass = Asn1TagClass.ContextDefined,
                        //    Data = SerialNumber.Value
                        //}
                    }
            }.GetBytes();
        }

        public static AuthorityKeyIdentifierExtension FromExtensionData(byte[] data) {
            var seq = Asn1Sequence.ReadNode(data);
            var node = (Asn1CustomNode)seq.Nodes[0];
            return new AuthorityKeyIdentifierExtension(node.Data);
        }
    }
}
