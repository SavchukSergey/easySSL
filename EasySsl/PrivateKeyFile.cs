using System.IO;
using System.Text;

namespace EasySsl {
    //http://www.drh-consultancy.demon.co.uk/pvk.html
    public class PrivateKeyFile {

        public uint Magic { get; set; }

        public uint Reserved { get; set; }

        public uint KeyType { get; set; }

        public uint Encrypted { get; set; }

        public uint SaltLen { get; set; }

        public byte[] Key { get; set; }

        public PrivateKeyFile() {
            Magic = 0xb0b5f11e;
        }

        public static PrivateKeyFile ReadFrom(string filePath) {
            using (var file = File.OpenRead(filePath)) {
                return ReadFrom(file);
            }
        }

        public static PrivateKeyFile ReadFrom(Stream stream) {
            using (var reader = new BinaryReader(stream, Encoding.UTF8, true)) {
                var res = new PrivateKeyFile {
                    Magic = reader.ReadUInt32(),
                    Reserved = reader.ReadUInt32(),
                    KeyType = reader.ReadUInt32(),
                    Encrypted = reader.ReadUInt32(),
                    SaltLen = reader.ReadUInt32(),
                };

                var keyLen = reader.ReadUInt32();
                res.Key = reader.ReadBytes((int)keyLen);
                return res;
            }
        }

        public void WriteTo(string filePath) {
            using (var file = File.OpenWrite(filePath)) {
                WriteTo(file);
            }
        }

        public void WriteTo(Stream stream) {
            using (var writer = new BinaryWriter(stream, Encoding.UTF8, true)) {
                writer.Write(Magic);
                writer.Write(Reserved);
                writer.Write(KeyType);
                writer.Write(Encrypted);
                writer.Write(SaltLen);
                writer.Write(Key.Length);
                writer.Write(Key);
            }
        }

        public byte[] ToArray() {
            using (var mem = new MemoryStream()) {
                WriteTo(mem);
                return mem.ToArray();
            }
        }
    }
}
