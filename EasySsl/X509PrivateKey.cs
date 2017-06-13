using System;
using System.Security.Cryptography;
using System.Text;
using Asn1;
using System.IO;

namespace EasySsl {
    public abstract class X509PrivateKey {

        public abstract AsymmetricAlgorithm CreateAsymmetricAlgorithm();

        public abstract byte[] SignData(byte[] data);

        public static X509PrivateKey From(Asn1Sequence sequence) {
            var idNode = new X509AlgorithmIdentifier((Asn1Sequence)sequence.Nodes[0]);
            var valueNode = (Asn1BitString)sequence.Nodes[1];
            if (idNode.Id == Asn1ObjectIdentifier.RsaEncryption) {
                return new RsaPrivateKey(valueNode);
            }
            throw new NotSupportedException();
        }

        public string ToPem() {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {PemName}-----");
            var data = ToAsn1();
            var bytes = data.GetBytes();
            sb.AppendLine(Base64.Convert(bytes));
            sb.AppendLine($"-----END {PemName}-----");
            return sb.ToString();
        }

        protected abstract string PemName { get; }

        public abstract X509AlgorithmIdentifier Algorithm { get; }

        public abstract Asn1Node ToAsn1();

        public abstract byte[] ToPvk();

        public X509PrivateKey Export(string filePath) {
            var pem = ToPem();
            using (var file = File.Open(filePath, FileMode.Create, FileAccess.ReadWrite, FileShare.None)) {
                using (var writer = new StreamWriter(file)) {
                    writer.Write(pem);
                    writer.Flush();
                    return this;
                }
            }
        }

        public PrivateKeyInfo GetPrivateKeyInfo() {
            return new PrivateKeyInfo {
                PrivateKeyAlgorithmIdentifier = X509AlgorithmIdentifier.RsaEncryption,
                PrivateKey = ToAsn1().GetBytes()
            };
        }


    }
}
