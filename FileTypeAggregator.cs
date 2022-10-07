using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class FileTypeAggregator
    {
        public IEnumerable<Signature> SignatureQuery { get; set; }
        public string HexString { get; set; }
        public string FileFullPath { get; set; }
        public List<Signature> SignatureList { get; set; }

        /// <summary>
        /// FileTypeAggregator constructor
        /// </summary>
        /// <param name="signatureQuery">List from which the records will be evaluated and sorted</param>
        /// <param name="hexString">Hexadecimal string that is used for identifying matching records</param>
        /// <param name="fileFullPath">File within which the containing byte sequence will analysed</param>
        /// <param name="signatureList">List containing the extensions.json file contents</param>
        public FileTypeAggregator(IEnumerable<Signature> signatureQuery, string hexString, string fileFullPath, in List<Signature> signatureList) 
        {
            SignatureQuery = signatureQuery;
            HexString = hexString;
            FileFullPath = fileFullPath;
            SignatureList = signatureList;
        }

        /// <summary>
        /// Returns an evaluated and sorted (ascending) DataTable that is prepared for printing to file or displaying within the console window
        /// </summary>
        /// <returns>Evaluated and sorted resultset</returns>
        public DataTable FetchResultsSortedAsc()
        {
            DataTable processedDataTable = new();
            DataColumn dataColumn;

            int columnCount = 7;

            for (int i = 0; i <= columnCount - 1; i++)
            {
                dataColumn = new DataColumn
                {
                    ColumnName = "Col" + i
                };
                processedDataTable.Columns.Add(dataColumn);
            }

            foreach (Signature sig in SignatureQuery)
            {
                string locatedPos = string.Empty;
                int posCounter = 0;
                int posValue = 0;

                foreach (var offsetLoc in GenericByteOperations.Offetlocations(searchHex: sig.Hex, fullHex: HexString)) //not duplicated
                {
                    if (Convert.ToInt32(offsetLoc) % 2 != 0)
                    {
                        continue;
                    }
                    posValue = Convert.ToInt32(offsetLoc) / 2;
                    string tempOutput = posValue == sig.Offset ? String.Format("0x{0:X}", Convert.ToInt32(offsetLoc) / 2) + 
                        " <--match" : String.Format("0x{0:X}",
                        Convert.ToInt32(offsetLoc) / 2);

                    if (posCounter == 0)
                    {
                        locatedPos = tempOutput.ToString();
                    }
                    else if (posCounter <= 5)
                    {
                        locatedPos = locatedPos + " / " + tempOutput.ToString();
                    }
                    else
                    {
                        locatedPos += " ***"; //if count is >= 6 then insert *** to denote multiple occurences of offset in several offsets 
                        break;
                    }
                    posCounter++;
                }

                if (locatedPos != String.Empty)
                {
                    string hexValueAtOffset = GenericByteOperations.ReadCustomByteRange(fileFullPath: FileFullPath,
                        startingHexOffSet: sig.Offset,
                        lengthToRead: Convert.FromHexString(sig.Hex).Length); 
                    var queryResultsToAdd = SignatureList.Where(x => x.Offset == sig.Offset && x.Hex == hexValueAtOffset && x.Name == sig.Name);
                    processedDataTable.Rows.Add(new object[] { queryResultsToAdd.Any() ? "high" : "low",
                                                sig.Name,
                                                sig.Offset.ToString(),
                                                sig.Hex,
                                                GenericByteOperations.HexToAscii(HexString: sig.Hex), 
                                                sig.Mime,
                                                locatedPos });
                }
            }

            processedDataTable.DefaultView.Sort = "Col0";
            processedDataTable = processedDataTable.DefaultView.ToTable();

            return processedDataTable;
        }

        
    }
}
