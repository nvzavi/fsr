using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fh_res
{
    /// <summary>
    /// Represents the staging signature object, into which the original file signature data, from the signatures.json file, is loaded.
    /// Object data from this object is prepared and passed to the Signature object (Signature.cs) 
    /// </summary>
    class StagingSignature
    {
        public string Name { get; set; }
        public List<string> Signs { get; set; }
        public string Mime { get; set; }
    }
}
