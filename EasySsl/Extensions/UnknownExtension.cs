using Asn1;

namespace EasySsl.Extensions {
    public class UnknownExtension : X509Extension {

        public override Asn1ObjectIdentifier Id { get; }

        private byte[] _data;

        public UnknownExtension(Asn1ObjectIdentifier id, byte[] data) {
            Id = id;
            _data = data;
        }

        protected override byte[] GetBytesCore() {
            return _data;
        }

    }
}
