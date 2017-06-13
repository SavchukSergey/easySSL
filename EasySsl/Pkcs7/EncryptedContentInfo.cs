using Asn1;

namespace EasySsl.Pkcs7 {
    public class EncryptedContentInfo {

        public Asn1ObjectIdentifier ContentType { get; set; }

        public Asn1ObjectIdentifier ContentEncryptionAlgorithmIdentifier { get; set; }

        public byte[] EncryptedContent { get; set; }

    }
}
