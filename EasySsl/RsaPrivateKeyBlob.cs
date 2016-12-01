using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace EasySsl {
    //2.2.2.9.1 RSA Private Key BLOB
    public class RsaPrivateKeyBlob {

        public RsaPrivateKeyBlob() {
        }

        public RsaPrivateKeyBlob(RSAParameters parameters) {
            Type = 0x07;
            Version = 0x02;
            Reserved = 0x0000;
            KeyAlg = 0x00002400;
            Magic = 0x32415352;
            BitLen = (uint)parameters.Modulus.Length;
            PubExp = ToUInt32(parameters.Exponent.Reverse().ToArray());
            Modulus = parameters.Modulus.Reverse().ToArray();
            P = parameters.P.Reverse().ToArray();
            Q = parameters.Q.Reverse().ToArray();
            Dp = parameters.DP.Reverse().ToArray();
            Dq = parameters.DQ.Reverse().ToArray();
            Iq = parameters.InverseQ.Reverse().ToArray();
            D = parameters.D.Reverse().ToArray();
        }

        public byte Type { get; set; }

        public byte Version { get; set; }

        public ushort Reserved { get; set; }

        public uint KeyAlg { get; set; }

        public uint Magic { get; set; }

        public uint BitLen { get; set; }

        public uint PubExp { get; set; }

        public byte[] Modulus { get; set; }

        public byte[] P { get; set; }

        public byte[] Q { get; set; }

        public byte[] Dp { get; set; }

        public byte[] Dq { get; set; }

        public byte[] Iq { get; set; }

        public byte[] D { get; set; }

        public static RsaPrivateKeyBlob Read(byte[] data) {
            using (var mem = new MemoryStream(data)) {
                return Read(mem);
            }
        }

        public static RsaPrivateKeyBlob Read(Stream stream) {
            using (var reader = new BinaryReader(stream, Encoding.UTF8, true)) {
                var res = new RsaPrivateKeyBlob {
                    Type = reader.ReadByte(),
                    Version = reader.ReadByte(),
                    Reserved = reader.ReadUInt16(),
                    KeyAlg = reader.ReadUInt32(),
                    Magic = reader.ReadUInt32(),
                    BitLen = reader.ReadUInt32(),
                    PubExp = reader.ReadUInt32()
                };

                res.Modulus = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 8.0));
                res.P = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 16.0));
                res.Q = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 16.0));
                res.Dp = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 16.0));
                res.Dq = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 16.0));
                res.Iq = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 16.0));
                res.D = reader.ReadBytes((int)Math.Ceiling(res.BitLen / 8.0));
                return res;
            }
        }

        public void WriteTo(Stream stream) {
            using (var writer = new BinaryWriter(stream, Encoding.UTF8, true)) {
                writer.Write(Type);
                writer.Write(Version);
                writer.Write(Reserved);
                writer.Write(KeyAlg);
                writer.Write(Magic);
                writer.Write(BitLen);
                writer.Write(PubExp);
                writer.Write(Modulus);
                writer.Write(P);
                writer.Write(Q);
                writer.Write(Dp);
                writer.Write(Dq);
                writer.Write(Iq);
                writer.Write(D);
            }
        }

        public byte[] ToArray() {
            using (var mem = new MemoryStream()) {
                WriteTo(mem);
                return mem.ToArray();
            }
        }

        public RSAParameters ToRsaParamaters() {
            return new RSAParameters {
                Modulus = Modulus.Reverse().ToArray(),
                P = P.Reverse().ToArray(),
                D = D.Reverse().ToArray(),
                Q = Q.Reverse().ToArray(),
                InverseQ = Iq.Reverse().ToArray(),
                Exponent = BitConverter.GetBytes(PubExp).Reverse().ToArray(),
                DQ = Dq.Reverse().ToArray(),
                DP = Dp.Reverse().ToArray()
            };
        }

        private static uint ToUInt32(byte[] data) {
            var res = 0L;
            for (var i = 0; i < data.Length; i++) {
                var bt = data[i];
                res = (res | ((long)bt << (8 * i)));
            }
            return (uint)res;
        }

    }
}
