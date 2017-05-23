using Asn1;

namespace EasySsl {
    public class CertificationRequestInfo {

        public Asn1Integer Version { get; set; }

        public X509Name Subject { get; set; }

        public SubjectPublicKeyInfo SubjectPublicKeyInfo { get; set; }

        //public Attributes Attributes {get; set; }

    }
}
