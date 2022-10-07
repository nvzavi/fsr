using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public abstract class FileSignatureResolverBase
    {
        /// <summary>
        /// Returns a string that represents the first few lines that are written to the windows console
        /// </summary>
        /// <param name="moduleName">Represents the name of 'FILE SIGNATURE RESOLVER v1.0  (BETA)' command module that was executed</param>
        public StringBuilder WriteFSRHeader(string moduleName)
        {
            StringBuilder sb = new();
            sb.AppendLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sb.AppendLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sb.AppendLine("-------------------------                              FILE SIGNATURE RESOLVER v1.0  (BETA)                                ---------------------");
            sb.AppendLine("-------------------------                                                    with added patching/carving/hashing features  ---------------------");
            sb.AppendLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sb.AppendLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sb.AppendLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
            sb.AppendLine($"\nModule:  {moduleName}");
            return sb;
        }

    }
}
