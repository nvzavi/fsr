using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class FileTypeService : FileSignatureResolverBase
    {
        public string FileFullPath { get; set; }
        public List<Signature> SignatureList { get; set; }
        public string FileOutputFullPath { get; set; }

        /// <summary>
        /// FileTypeService constructor
        /// </summary>
        /// <param name="fileFullPath">Full path of the file to be analysed, evaluated and sorted (ascending)</param>
        /// <param name="signatureList">List containing the extensions.json file contents</param>
        public FileTypeService(string fileFullPath,in List<Signature> signatureList) 
        {
            FileFullPath = fileFullPath;
            SignatureList = signatureList;
            FileOutputFullPath = "-1";
        }

        /// <summary>
        /// FileTypeService constructor
        /// </summary>
        /// <param name="fileFullPath">Full path of the file to be analysed, evaluated and sorted (ascending)</param>
        /// <param name="signatureList">List containing the extensions.json file contents</param>
        /// <param name="fileOutputFullPath">OPTIONAL:  Full path of the file to which the results will be written.  Default to '-1' if no value is passed in the method call statement</param>
        public FileTypeService(string fileFullPath, in List<Signature> signatureList, string fileOutputFullPath)
        {
            FileFullPath = fileFullPath;
            SignatureList = signatureList;
            FileOutputFullPath = fileOutputFullPath;
        }

        /// <summary>
        /// Analyse a specified file and return a 'possible file type associations' result that is based on degree of probability (high or low). 
        /// </summary>
        public void GetFileType()
        {
            string fullHexString = String.Empty;
            try
            {
                if (!File.Exists(path: FileFullPath))
                {
                    throw new Exception($"File '{FileFullPath}' not found!!!");
                }
                if (FileOutputFullPath != "-1")
                {
                    if (!Directory.Exists(Path.GetDirectoryName(FileOutputFullPath)))
                    {
                        throw new Exception($"Output directory '{FileOutputFullPath}' is not valid!!!");
                    }

                    if (File.Exists(FileOutputFullPath))
                    {
                        Random random = new();
                        FileOutputFullPath = Path.GetDirectoryName(FileOutputFullPath) + "\\" + 
                            Path.GetFileName(FileOutputFullPath)[..Path.GetFileName(FileOutputFullPath).IndexOf(".")] + 
                            "_fhgen_" + random.Next(10000)
                            + Path.GetFileName(FileOutputFullPath)[Path.GetFileName(FileOutputFullPath).IndexOf(".")..];

                        StreamWriter writer = new(FileOutputFullPath);
                        writer.Close();
                    }
                    else
                    {
                        StreamWriter writer = new(FileOutputFullPath);
                        writer.Close();
                    }
                }

                byte[] bytesFile;
                int byteSize = 0;
                using (FileStream fs = File.OpenRead(FileFullPath))
                {
                    byteSize = (int)fs.Length;
                    bytesFile = new byte[byteSize];
                    fs.Read(bytesFile, 0, byteSize);
                    fs.Close();
                }

                fullHexString = BitConverter.ToString(bytesFile).Replace("-", "");

                Console.WriteLine("***Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");
                var queryResult = SignatureList.Where(x => fullHexString.Contains(x.Hex));
                Console.WriteLine($"\nFile:  {FileFullPath}");
                GetMoreFileDetails(); 
                int totalRecords = 0;

                if (queryResult.Any())
                {
                    FileTypeAggregator fileTypeAggregator = new (signatureQuery: queryResult, hexString: fullHexString, fileFullPath: FileFullPath, signatureList: SignatureList);
                    DataTable sortedResultsDataTable;
                    sortedResultsDataTable = fileTypeAggregator.FetchResultsSortedAsc().Copy();
                    totalRecords = sortedResultsDataTable.Rows.Count;
                    Console.WriteLine($"\nTotal Matches Found:  {totalRecords}");

                    if (FileOutputFullPath == "-1")
                    {
                        SendOutputToScreen(resultsDataTable: sortedResultsDataTable); 
                    }
                    else
                    {
                        SendOutputToFile(resultsDataTable: sortedResultsDataTable); 
                    }
                }
                else
                {
                    Console.WriteLine("\nNo matching file types were found!!!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error:" + ex.Message);
            }
        }

        /// <summary>
        /// Return additional file attributes for a specified file
        /// </summary>
        public void GetMoreFileDetails()
        {
            LocalFile localFile = new(FileFullPath);
            Console.WriteLine("\nFile Attributes --------------------------------------------------------------------------------");
            Console.WriteLine("{0,-15} {1,-64}", "File Name:", localFile.Name);
            Console.WriteLine("{0,-15} {1,-64}", "File Size:", localFile.FileSize + " bytes");
            Console.WriteLine("{0,-15} {1,-64}", "Created Date:", localFile.CreatedDate);
            Console.WriteLine("{0,-15} {1,-64}", "Accessed Date:", localFile.LastAccessed);
            Console.WriteLine("{0,-15} {1,-64}", "Modified Date:", localFile.LastModifiedDate);
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }

        /// <summary>
        /// Output the results of the GetFileType method to a specified file. 
        /// </summary>
        /// <param name="resultsDataTable">DataTable from which the results will be extracted</param>
        private void SendOutputToFile(DataTable resultsDataTable)
        {
            using FileStream fs = new(FileOutputFullPath, FileMode.Append, FileAccess.Write);
            using StreamWriter sw = new(fs);
            sw.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sw.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sw.WriteLine("-------------------------                              FILE SIGNATURE RESOLVER v1.0  (BETA)                                ---------------------");
            sw.WriteLine("-------------------------                                                    with added patching/carving/hashing features  ---------------------");
            sw.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sw.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            sw.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
            sw.WriteLine("Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");
            sw.WriteLine("\nModule:  Get possible file signature/s");
            sw.WriteLine("");
            sw.WriteLine($"File:  {FileFullPath}");
            sw.WriteLine($"Processed Date:  {DateTime.Now}");
            sw.WriteLine($"Total Matches Found:  {resultsDataTable.Rows.Count}");
            sw.WriteLine("");
            foreach (DataRow dRow in resultsDataTable.Rows)
            {
                sw.WriteLine("{0,-30} {1,-64}", "Probability:", dRow[0].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "Extension:", dRow[1].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "Offset (expected):", dRow[2].ToString() + " (base 10) - " + String.Format("0x{0:X}",
                    Convert.ToInt32(dRow[2])) + "(base 16)");
                sw.WriteLine("{0,-30} {1,-64}", "Hexadecimal (expected):", dRow[3].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "ASCII (expected):", dRow[4].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "Mime:", dRow[5].ToString());
                sw.WriteLine($"\nAdditional file signature entries for '{dRow[1]}' with hexadecimal value '{dRow[3]}' were found within the current file");
                sw.WriteLine("{0,-30} {1,-64}", "Located Offset/s:", dRow[6].ToString());
                sw.WriteLine("");
                sw.WriteLine("");
                sw.WriteLine("----------------------------------------------------------------------------------------------");
                sw.WriteLine("");
                sw.WriteLine("");
            }
            Console.WriteLine("Output successfully written to " + FileOutputFullPath);
        }

        /// <summary>
        /// Returns the result of the GetFileType method to the console window
        /// </summary>
        /// <param name="resultsDataTable">DataTable from which the results will be extracted</param>
        private void SendOutputToScreen(DataTable resultsDataTable)
        {
            Console.WriteLine("\nResults for " + FileFullPath + " is displayed in order from high to low probability.");
            foreach (DataRow dRow in resultsDataTable.Rows)
            {
                Console.WriteLine("\n{0,-30} {1,-64}", "Probability:", dRow[0].ToString());
                Console.WriteLine("{0,-30} {1,-64}", "Extension:", dRow[1].ToString());
                Console.WriteLine("{0,-30} {1,-64}", "Offset (expected):", dRow[2].ToString() + " (base 10) - " + String.Format("0x{0:X}",
                    Convert.ToInt32(dRow[2])) + "(base 16)");
                Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal (expected):", dRow[3].ToString());
                Console.WriteLine("{0,-30} {1,-64}", "ASCII (expected):", dRow[4].ToString());
                Console.WriteLine("{0,-30} {1,-64}", "Mime:", dRow[5].ToString());
                Console.WriteLine($"\nAdditional file signature entries for '{dRow[1]}' with hexadecimal value '{dRow[3]}' were found within the current file");
                Console.WriteLine("{0,-30} {1,-64}", "Located Offset/s:", dRow[6].ToString());
                Console.WriteLine("\n\n----------------------------------------------------------------------------------------------");
            }
        }
    }
}
