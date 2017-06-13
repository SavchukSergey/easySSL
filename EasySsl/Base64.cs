using System.Text;

namespace EasySsl {
    public static class Base64 {

        public static string Convert(byte[] data) {
            var str = System.Convert.ToBase64String(data);
            var sb = new StringBuilder();
            for (var i = 0; i < str.Length; i += 76) {
                var len = System.Math.Min(76, str.Length - i);
                sb.Append(str, i, len);
                sb.AppendLine();
            }
            return sb.ToString().Trim();
        }
    }
}
