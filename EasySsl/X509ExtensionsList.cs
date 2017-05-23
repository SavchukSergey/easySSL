using System.Collections.Generic;
using System.Linq;
using Asn1;
using System;

namespace EasySsl {
    public class X509ExtensionsList : List<X509Extension> {

        public void SetAuthorityKeyIdentifier(byte[] issuerKeyIdentifier) {
            if (issuerKeyIdentifier == null) throw new ArgumentNullException(nameof(issuerKeyIdentifier));

            Add(new X509Extension {
                Id = Asn1ObjectIdentifier.AuthorityKeyIdentifier,
                Value = new Asn1Sequence {
                    Nodes = {
                        new Asn1CustomNode(0x00, Asn1TagForm.Primitive, Asn1TagClass.ContextDefined) {
                            Data = issuerKeyIdentifier
                        }//,
                        //new Asn1CustomNode(0x01, Asn1TagForm.Primitive) {
                        //    TagClass = Asn1TagClass.ContextDefined,
                        //    Data = new Asn1Utf8String(Subject.CommonName).GetBytes()
                        //},
                        //new Asn1CustomNode(0x02, Asn1TagForm.Primitive) {
                        //    TagClass = Asn1TagClass.ContextDefined,
                        //    Data = SerialNumber.Value
                        //}
                    }
                }.GetBytes()
            });
        }

        public byte[] GetAuthorityKeyIdentifier() {
            var data = GetExtensionValue(Asn1ObjectIdentifier.AuthorityKeyIdentifier);
            if (data == null) return null;
            var seq = (Asn1Sequence)Asn1Node.ReadNode(data);
            var idNode = seq.Nodes.FirstOrDefault(item => item.Is(Asn1TagClass.ContextDefined, 0x00));
            return ((Asn1CustomNode)idNode)?.Data;
        }

        public void SetSubjectKeyIdentifier(byte[] issuerKeyIdentifier) {
            Add(new X509Extension {
                Id = Asn1ObjectIdentifier.SubjectKeyIdentifier,
                Value = new Asn1OctetString(issuerKeyIdentifier).GetBytes()
            });
        }

        public byte[] GetSubjectKeyIdentifier() {
            var data = GetExtensionValue(Asn1ObjectIdentifier.SubjectKeyIdentifier);
            if (data == null) return null;
            var seq = (Asn1OctetString)Asn1Node.ReadNode(data);
            return seq.Data;
        }

        private byte[] GetExtensionValue(Asn1ObjectIdentifier id) {
            var ext = this.FirstOrDefault(e => e.Id == id);
            return ext?.Value;
        }
    }
}
