using Asn1;

namespace EasySsl.Pkcs7 {
    //https://tools.ietf.org/html/rfc5652
    public class EncryptedData {

        public Asn1Integer Version { get; set; } = new Asn1Integer(0);

        public EncryptedContentInfo EncryptedContentInfo { get; set; }

    }
}
