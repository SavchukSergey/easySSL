using System;
using System.Security.Cryptography;
using Asn1;

namespace EasySsl {
    public class X509TbsCertificate {

        public X509TbsCertificate() {
        }

        public X509TbsCertificate(Asn1Sequence node) {
            var i = 0;
            var subnode = node.Nodes[i++];

            if (subnode.Is(Asn1TagClass.ContextDefined, 0x00)) {
                Version = new X509Version(subnode);
                subnode = node.Nodes[i++];
            }

            SerialNumber = (Asn1Integer)subnode;
            subnode = node.Nodes[i++];

            SignatureAlgorithm = new X509AlgorithmIdentifier((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            Issuer = new X509Name((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            Validity = new X509Validity((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            Subject = new X509Name((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            SubjectPublicKeyInfo = SubjectPublicKeyInfo.From((Asn1Sequence)subnode);
            subnode = node.Nodes[i++];

            if (subnode.Is(Asn1TagClass.ContextDefined, 0x01)) {
                //issuerUniqueId
                throw new NotImplementedException();
            }

            if (subnode.Is(Asn1TagClass.ContextDefined, 0x02)) {
                //subjectUniqueId
                throw new NotImplementedException();
            }

            if (subnode.Is(Asn1TagClass.ContextDefined, 0x03)) {
                var extSeq = subnode.Nodes[0];
                foreach (var extNode in extSeq.Nodes) {
                    Extensions.Add(new X509Extension((Asn1Sequence)extNode));
                }
            }

        }

        public X509Version Version { get; set; } = new X509Version(3);

        public Asn1Integer SerialNumber { get; set; }

        public X509AlgorithmIdentifier SignatureAlgorithm { get; set; }

        public X509Name Issuer { get; set; }

        public X509Validity Validity { get; set; }

        public X509Name Subject { get; set; }

        public Asn1BitString UniqueIdentifier { get; set; }

        public SubjectPublicKeyInfo SubjectPublicKeyInfo { get; set; }

        //public X509PublicKey PublicKey { get; set; }

        public AsymmetricAlgorithm PrivateKey { get; set; }

        public X509ExtensionsList Extensions { get; } = new X509ExtensionsList();

        public Asn1Node ToAsn1() {
            if (SerialNumber == null) throw new Exception("Serial number is not generated");
            var res = new Asn1Sequence {
                Nodes = {
                    Version.ToAsn1(),
                    SerialNumber,
                    SignatureAlgorithm.ToAsn1(),
                    Issuer.ToAsn1(),
                    Validity.ToAsn1(),
                    Subject.ToAsn1(),
                    SubjectPublicKeyInfo.ToAsn1()
                }
            };
            if (Extensions.Count > 0) {
                var extsSeq = new Asn1Sequence();
                foreach (var ext in Extensions) {
                    extsSeq.Nodes.Add(ext.ToAsn1());
                }
                var extsNode = new Asn1CustomNode(0x03, Asn1TagForm.Constructed) {
                    TagClass = Asn1TagClass.ContextDefined,
                    Nodes = { extsSeq }
                };
                res.Nodes.Add(extsNode);
            }
            return res;
        }

    }
}
