using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fh_res
{
    /// <summary>
    /// Represents the final file signature object into which the object data is loaded from the signature staging area (StagingSignature.cs)
    /// </summary>
    class Signature
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public int Offset { get; set; }
        public string Hex { get; set; }
        public string Mime { get; set; }
    }
}
