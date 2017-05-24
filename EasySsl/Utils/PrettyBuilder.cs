using System.IO;

namespace EasySsl.Utils {
    public class PrettyBuilder {

        private int _indentation;

        private TextWriter _writer;

        public PrettyBuilder(TextWriter writer) {
            _writer = writer;
        }

        public void Append(string val) {
            var lines = val.Split('\r', '\n');
            foreach (var line in lines) {
                if (!string.IsNullOrWhiteSpace(line)) {
                    AppendSingleLine(line);
                }
            }
        }

        public void AppendSingleLine(string val) {
            for (var i = 0; i < _indentation; i++) {
                _writer.Write(' ');
            }
            _writer.WriteLine(val);
        }

        public void IndentRight() {
            _indentation += 2;
        }

        public void IndentLeft() {
            _indentation -= 2;
        }
    }
}
