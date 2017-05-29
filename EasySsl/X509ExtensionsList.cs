using System;
using System.Collections.Generic;
using System.Linq;
using EasySsl.Extensions;

namespace EasySsl {
    public class X509ExtensionsList : List<X509Extension> {

        public byte[] GetAuthorityKeyIdentifier() {
            return GetExtension<AuthorityKeyIdentifierExtension>()?.IssuerKeyIdentifier;
        }

        public byte[] GetSubjectKeyIdentifier() {
            return GetExtension<SubjectKeyIdentifierExtension>()?.SubjectKeyIdentifier;
        }

        public X509ExtensionsList SetAuthorityKeyIdentifier(byte[] id) {
            if (id == null) throw new ArgumentNullException(nameof(id));
            var issuerKeyIdentifier = new AuthorityKeyIdentifierExtension(id);
            Add(issuerKeyIdentifier);
            return this;
        }

        public X509ExtensionsList SetSubjectKeyIdentifier(byte[] id) {
            if (id == null) throw new ArgumentNullException(nameof(id));
            var subjectKeyIdentifier = new SubjectKeyIdentifierExtension(id);
            Add(subjectKeyIdentifier);
            return this;
        }

        public X509ExtensionsList SetBasicConstraint(BasicConstraintExtension data) {
            Add(data);
            return this;
        }

        public X509ExtensionsList SetAuthorityInfoAccess(AuthorityInfoAccessExtension data) {
            Add(data);
            return this;
        }

        public T GetExtension<T>() where T : X509Extension {
            return this.OfType<T>().FirstOrDefault();
        }

    }
}
