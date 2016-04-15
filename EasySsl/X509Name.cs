using System.Collections.Generic;
using System.Linq;
using Asn1;

namespace EasySsl {
    //https://tools.ietf.org/html/rfc5280#section-4.1.2.4
    //https://www.ietf.org/rfc/rfc1779.txt
    public class X509Name {

        private readonly IList<X509RelativeDistinguishedName> _items = new List<X509RelativeDistinguishedName>();

        public X509Name() {
        }

        public X509Name(Asn1Sequence node) {
            foreach (var subnode in node.Nodes) {
                var set = (Asn1Set)subnode;
                var item = new X509RelativeDistinguishedName(set);
                _items.Add(item);
            }
        }

        public string CommonName {
            get { return Get(Asn1ObjectIdentifier.CommonName); }
            set { Set(Asn1ObjectIdentifier.CommonName, value); }
        }

        public string Organization {
            get { return Get(Asn1ObjectIdentifier.OrganizationName); }
            set { Set(Asn1ObjectIdentifier.OrganizationName, value); }
        }

        public string OrganizationalUnit {
            get { return Get(Asn1ObjectIdentifier.OrganizationalUnitName); }
            set { Set(Asn1ObjectIdentifier.OrganizationalUnitName, value); }
        }

        public string Country { get; set; }

        private string Get(Asn1ObjectIdentifier id) {
            var item = _items.FirstOrDefault(i => i.Id == id);
            return item?.Value;
        }

        private void Set(Asn1ObjectIdentifier id, string value) {
            var item = _items.FirstOrDefault(i => i.Id == id);
            if (item == null) {
                item = new X509RelativeDistinguishedName(id);
                _items.Add(item);
            }
            item.Value = value;
        }

        public Asn1Node ToAsn1() {
            var res = new Asn1Sequence();
            foreach (var item in _items) {
                res.Nodes.Add(item.ToAsn1());
            }
            return res;
        }
    }
}
