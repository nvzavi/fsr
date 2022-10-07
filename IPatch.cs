using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public interface IPatch
    {
        void PatchBytes();
        void PrintRevertByteOptions();
        bool IsPatchSuccessfull();
    }
}
