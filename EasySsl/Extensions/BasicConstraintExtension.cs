using Asn1;
using System;

namespace EasySsl.Extensions {
    public class BasicConstraintExtension : X509Extension {

        public override Asn1ObjectIdentifier Id => Asn1ObjectIdentifier.BasicConstraints;

        public bool Authority { get; set; }

        public ulong? PathLengthConstraint { get; set; }

        public BasicConstraintExtension() {
            Critical = true;
        }

        public static BasicConstraintExtension FromExtensionData(byte[] data) {
            if (data == null) throw new ArgumentNullException(nameof(data));
            var seq = Asn1Sequence.ReadNode(data);
            bool authority = false;
            ulong? pathLengthConstraint = null;
            if (seq.Nodes.Count > 0) {
                authority = ((Asn1Boolean)seq.Nodes[0]).Value;
                if (seq.Nodes.Count > 1) {
                    pathLengthConstraint = ((Asn1Integer)seq.Nodes[1]).ToUInt64();
                }
            }
            return new BasicConstraintExtension {
                Authority = authority,
                PathLengthConstraint = pathLengthConstraint
            };
        }

        protected override byte[] GetBytesCore() {
            var seq = new Asn1Sequence { Nodes = { new Asn1Boolean(Authority) } };
            if (PathLengthConstraint.HasValue) {
                seq.Nodes.Add(new Asn1Integer((long)PathLengthConstraint.Value));
            }
            return seq.GetBytes();
        }

    }
}
