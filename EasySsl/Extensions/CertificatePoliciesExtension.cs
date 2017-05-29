using Asn1;

namespace EasySsl.Extensions {
    public class CertificatePoliciesExtension : X509Extension {

        public override Asn1ObjectIdentifier Id => Asn1ObjectIdentifier.CertificatePolicies;

        protected override byte[] GetBytesCore() {
            return new Asn1Sequence {
                Nodes = {
                   new Asn1Sequence {
                       Nodes = {
                           new Asn1ObjectIdentifier("2.16.840.1.114413.1.7.23.1"),
                           new Asn1Sequence {
                               Nodes = {
                                   new Asn1Sequence {
                                       Nodes = {
                                            new Asn1ObjectIdentifier("1.3.6.1.5.5.7.2.1"),
                                            new Asn1PrintableString {
                                                Value = "http://certificates.godaddy.com/repository/"
                                            }
                                       }
                                   }
                               }
                           }
                       }
                   }
               }
            }.GetBytes();
        }
    }
}
