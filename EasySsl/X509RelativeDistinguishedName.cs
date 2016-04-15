using System;
using Asn1;

namespace EasySsl {
    public class X509RelativeDistinguishedName {

        public Asn1ObjectIdentifier Id { get; set; }

        public string Value { get; set; }

        public X509RelativeDistinguishedName(Asn1Set node) {
            var seq = node.Nodes[0];
            Id = (Asn1ObjectIdentifier)seq.Nodes[0];
            Value = GetStringValue(seq.Nodes[1]);
        }

        public X509RelativeDistinguishedName(Asn1ObjectIdentifier id) {
            Id = id;
        }

        private string GetStringValue(Asn1Node node) {
            if (node is Asn1PrintableString) return ((Asn1PrintableString)node).Value;
            if (node is Asn1Utf8String) return ((Asn1Utf8String)node).Value;
            throw new NotSupportedException();
        }


        public Asn1Node ToAsn1() {
            var res = new Asn1Set {
                Nodes = {
                    new Asn1Sequence {
                        Nodes = {
                            Id,
                            new Asn1Utf8String { Value = Value}
                        }
                    }
                }
            };
            return res;
        }
    }
}
