using System.Collections.Generic;

namespace EasySsl.Extensions {
    public class AuthorityInfoAccess {

        public IList<AuthorityAccessDescription> Methods { get; } = new List<AuthorityAccessDescription>();

    }
}
