using System;
using Asn1;

namespace EasySsl {
    //https://tools.ietf.org/html/rfc5280#section-4.1.2.5
    public class X509Validity {

        public DateTimeOffset NotBefore { get; set; }

        public DateTimeOffset NotAfter { get; set; }

        public X509Validity() {
        }

        public X509Validity(Asn1Sequence node) {
            NotBefore = GetDate(node.Nodes[0]);
            NotAfter = GetDate(node.Nodes[1]);
        }

        private static DateTimeOffset GetDate(Asn1Node node) {
            if (node is Asn1UtcTime) {
                return ((Asn1UtcTime)node).Value;
            }
            //todo: GeneralizedTime
            throw new NotSupportedException();
        }

        public override string ToString() {
            return $"{NotBefore} - {NotAfter}";
        }

        public Asn1Node ToAsn1() {
            return new Asn1Sequence {
                Nodes = {
                    new Asn1UtcTime { Value = NotBefore },
                    new Asn1UtcTime { Value = NotAfter }
                }
            };
        }
    }
}
