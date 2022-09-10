using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fh_res
{
    class Header
    {
        public int ID { get; set; }
        public string HexValues { get; set; }
        public string Type { get; set; }

        public Header(int iD, string hexValues, string type)
        {
            ID = iD;
            HexValues = hexValues;
            Type = type;
        }

        public override string ToString()
        {
            return $"Value:\t{HexValues}\t|\t{Type}";
        }
    }
}
