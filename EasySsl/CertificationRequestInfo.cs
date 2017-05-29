using Asn1;
using EasySsl.Extensions;

namespace EasySsl {
    public class CertificationRequestInfo {

        public Asn1Integer Version { get; set; }

        public X509Name Subject { get; set; }

        public SubjectPublicKeyInfo SubjectPublicKeyInfo { get; set; }

        public X509ExtensionsList RequestedExtensions { get; } = new X509ExtensionsList();

        public CertificationRequestInfo SetBasicConstraint(BasicConstraintExtension data) {
            RequestedExtensions.SetBasicConstraint(data);
            return this;
        }

        public CertificationRequestInfo SetAuthorityInfoAccess(AuthorityInfoAccessExtension data) {
            RequestedExtensions.SetAuthorityInfoAccess(data);
            return this;
        }

    }
}
