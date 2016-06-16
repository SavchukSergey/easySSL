using System;
using System.Security.Cryptography;
using System.Text;
using Asn1;

namespace EasySsl {
    public abstract class X509PublicKey {

        public abstract AsymmetricAlgorithm CreateAsymmetricAlgorithm();

        public abstract byte[] GenerateIdentifier();

        public string ToPem() {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {PemName}-----");
            var data = ToAsn1();
            var bytes = data.GetBytes();
            sb.AppendLine(Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine($"-----END {PemName}-----");
            return sb.ToString();
        }

        protected abstract string PemName { get; }

        public abstract X509AlgorithmIdentifier Algorithm { get; }

        public abstract Asn1Node ToAsn1();

        public SubjectPublicKeyInfo GetSubjectPublicKeyInfo() {
            return new SubjectPublicKeyInfo {
                Algorithm = Algorithm,
                SubjectPublicKey = ToAsn1().GetBytes()
            };
        }

    }
}
