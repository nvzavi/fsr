using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    /// <summary>
    /// Represents the staging signature object, into which the original file signature data, from the signatures.json file, is loaded.
    /// Object data from this object is prepared and passed to the Signature object (Signature.cs) 
    /// </summary>
    public class StagingSignature
    {
        public string Name { get; set; }
        public List<string> Signs { get; set; }
        public string Mime { get; set; }

        public StagingSignature(string name, List<string> signs, string mime)
        {
            Name = name;
            Signs = signs;
            Mime = mime;
        }
    }
}
