using Asn1;

namespace EasySsl.Extensions {
    public class SubjectKeyIdentifierExtension : X509Extension {

        public override Asn1ObjectIdentifier Id => Asn1ObjectIdentifier.SubjectKeyIdentifier;

        public byte[] SubjectKeyIdentifier { get; set; }

        public SubjectKeyIdentifierExtension() {
        }

        public SubjectKeyIdentifierExtension(byte[] id) {
            SubjectKeyIdentifier = id;
        }

        protected override byte[] GetBytesCore() {
            return new Asn1OctetString(SubjectKeyIdentifier).GetBytes();
        }

    }
}
