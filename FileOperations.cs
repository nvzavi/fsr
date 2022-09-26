using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data;
using System.Collections;
using System.Security.Permissions;
using System.Security;
using System.Reflection.PortableExecutable;

namespace fh_res
{
    static class FileOperations
    {
        /// <summary>
        /// Load the signatures.json file into a type List 
        /// </summary>
        /// <param name="signatureListFilePath">Full path to the signatures.json file</param>
        /// <param name="signatureList">List into which the signatures.json file is loaded</param>
        public static void LoadJson(string signatureListFilePath, ref List<Signature> signatureList)
        {
            try
            {
                List<StagingSignature> stagingSignature = new();
                using StreamReader r = new(signatureListFilePath);
                string json = r.ReadToEnd(); 
                var jo = JObject.Parse(json); 
                foreach (var kv in jo)
                {
                    if (kv.Value != null)
                    {
                        var deserializable = kv.Value.ToString(); 

                        if (kv.Key != null) 
                        {
                            var sign = JsonConvert.DeserializeObject<StagingSignature>(deserializable);
                            if (sign != null)
                            {
                                sign.Name = kv.Key;
                                stagingSignature.Add(new StagingSignature(sign.Name, sign.Signs, sign.Mime));
                            }
                        }
                    }
                }

                int stagingCounter = 1;
                foreach (StagingSignature signs in stagingSignature)
                {
                    foreach (var val in signs.Signs) 
                    {
                        int offset = Convert.ToInt32(val[..val.IndexOf(',')]); 
                        string hexValue = val[(val.IndexOf(',') + 1)..];
                        signatureList.Add(new Signature(stagingCounter, signs.Name, offset, hexValue, signs.Mime));
                        stagingCounter++;
                    }
                }
                r.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error:" + ex.Message);
            }     
        }

        /// <summary>
        /// Returns a ASCII representation of a hexadecimal string
        /// </summary>
        /// <param name="HexString">Hexadecimal string that will be represented as ASCII</param>
        /// <param name="lengthOfHexString">OPTIONAL:  Length of hexdecimal string to read</param>
        /// <returns>ASCII representation of a specified hexadecimal string</returns>
        private static string HexToAscii(string HexString, int lengthOfHexString = 0) 
        {

            string ascii = string.Empty;
            string hex = String.Empty;

            if (lengthOfHexString != 0) { HexString = HexString[..lengthOfHexString]; } 

            string[] splitValues = HexString.Chunk(2).Select(x => new string(x)).ToArray();

            foreach (string hValue in splitValues)
            {
                int value = Convert.ToInt32(hValue, 16);
                if (value > 31) //ignore non-printable characters
                {
                    char charValue = (char)value;
                    ascii += charValue.ToString();
                }
            }
            return ascii;
        }

        /// <summary>
        /// Returns an evaluated and sorted (ascending) DataTable that is prepared for printing to file or displaying within the console window
        /// </summary>
        /// <param name="signatureQuery">List from which the records will be evaluated and sorted</param>
        /// <param name="hexString">Hexadecimal string that is used for identifying matching records</param>
        /// <param name="fileFullPath">File within which the containing byte sequence will analysed</param>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        /// <returns>Evaluated and sorted resultset</returns>
        private static DataTable FetchResultsSortedAsc(IEnumerable<Signature> signatureQuery, string hexString, string fileFullPath, in List<Signature> signatureList)
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

            foreach (Signature sig in signatureQuery) 
            {
                string locatedPos = string.Empty;
                int posCounter = 0;
                int posValue = 0;

                foreach (var offsetLoc in Offetlocations(searchHex: sig.Hex, fullHex: hexString))
                {
                    if (Convert.ToInt32(offsetLoc) % 2 != 0) 
                    {
                        continue;
                    }
                    posValue = Convert.ToInt32(offsetLoc) / 2; 
                    string tempOutput = posValue == sig.Offset ? String.Format("0x{0:X}", Convert.ToInt32(offsetLoc) / 2) + " <--match" : String.Format("0x{0:X}",
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

                if (locatedPos!=String.Empty) 
                {
                    string hexValueAtOffset = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: sig.Offset, lengthToRead: Convert.FromHexString(sig.Hex).Length); 
                    var queryResultsToAdd = signatureList.Where(x => x.Offset == sig.Offset && x.Hex == hexValueAtOffset && x.Name == sig.Name); 
                    processedDataTable.Rows.Add(new object[] { queryResultsToAdd.Any() ? "high" : "low",
                                                sig.Name,
                                                sig.Offset.ToString(),
                                                sig.Hex,
                                                FileOperations.HexToAscii(HexString: sig.Hex),
                                                sig.Mime,
                                                locatedPos });
                }
            }

            processedDataTable.DefaultView.Sort = "Col0";
            processedDataTable = processedDataTable.DefaultView.ToTable();

            return processedDataTable;
        }

        /// <summary>
        /// Returns the result of the GetFileType method to the console window
        /// </summary>
        /// <param name="resultsDataTable">DataTable from which the results will be extracted</param>
        private static void SendOutputToScreen(DataTable resultsDataTable)
        {
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

        /// <summary>
        /// Output the results of the GetFileType method to a specified file. 
        /// </summary>
        /// <param name="fileFullPath">Full path of the file that was analysed, evaluated and sorted (ascending)</param>
        /// <param name="fileOutputFullPath">Full path of the file to which the results will be written</param>
        /// <param name="resultsDataTable">DataTable from which the results will be extracted</param>
        private static void SendOutputToFile(string fileFullPath, string fileOutputFullPath, DataTable resultsDataTable)
        {
            using FileStream fs = new(fileOutputFullPath, FileMode.Append, FileAccess.Write);
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
            sw.WriteLine($"File:  {fileFullPath}");
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
            Console.WriteLine("Output successfully written to " + fileOutputFullPath);

        }

        /// <summary>
        /// Analyse a specified file and return a 'possible file type associations' result that is based on degree of probability (high or low). 
        /// <para>It returns an evaluated result with the following headings:  Probability, Extension, Offset (expected), Hexadecimal (expected), Mime, Hexadecimal at Offset, ASCII at Offset, Located Offset\s</para> 
        /// <para>If the OPTIONAL parameter 'fileOutputFullPath' is passed when calling this method, the results will be written to the specified file assigned to the 'fileOutputFullPath' parameter</para>
        /// <para>If the OPTIONAL parameter 'fileOutputFullPath' is not passed when calling this method, a default value (-1) is passed and the results will be written to the console window.</para>
        /// </summary>
        /// <param name="fileFullPath">Full path of the file to be analysed, evaluated and sorted (ascending)</param>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        /// <param name="fileOutputFullPath">OPTIONAL:  Full path of the file to which the results will be written.  Default to '-1' if no value is passed in the method call statement</param>
        public static void GetFileType(string fileFullPath, in List<Signature> signatureList, string fileOutputFullPath = "-1") 
        {
            string fullHexString = String.Empty;
            try 
            {
                if (!File.Exists(path: fileFullPath)) 
                {
                    throw new Exception($"File '{fileFullPath}' not found!!!");
                }
                if (fileOutputFullPath!="-1")
                {             
                    if (!Directory.Exists(Path.GetDirectoryName(fileOutputFullPath)))
                    {
                        throw new Exception($"Output directory '{fileOutputFullPath}' is not valid!!!");
                    }

                    if (File.Exists(fileOutputFullPath))
                    {
                        Random random = new();
                        fileOutputFullPath = Path.GetDirectoryName(fileOutputFullPath) + "\\" + Path.GetFileName(fileOutputFullPath)[..Path.GetFileName(fileOutputFullPath).IndexOf(".")] + "_fhgen_" + random.Next(10000)
                            + Path.GetFileName(fileOutputFullPath)[Path.GetFileName(fileOutputFullPath).IndexOf(".")..];

                        StreamWriter writer = new(fileOutputFullPath);
                        writer.Close();
                    }
                    else 
                    { 
                        StreamWriter writer = new(fileOutputFullPath);
                        writer.Close();
                    }           
                }

                byte[] bytesFile;
                int byteSize = 0;
                using (FileStream fs = File.OpenRead(fileFullPath))
                {
                    byteSize = (int)fs.Length; 
                    bytesFile = new byte[byteSize];
                    fs.Read(bytesFile, 0, byteSize); 
                    fs.Close();
                }

                fullHexString = BitConverter.ToString(bytesFile).Replace("-", "");  
                WriteFSRHeader($"Get possible file signature/s");
                Console.WriteLine("***Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");
                var queryResult = signatureList.Where(x => fullHexString.Contains(x.Hex)); 
                Console.WriteLine($"\nFile:  {fileFullPath}");
                GetMoreFileDetails(fileFullPath: fileFullPath);
                int totalRecords = 0;

                if (queryResult.Any())
                {
                    DataTable sortedResultsDataTable;
                    sortedResultsDataTable = FetchResultsSortedAsc(signatureQuery: queryResult, hexString: fullHexString, fileFullPath: fileFullPath, signatureList: in signatureList).Copy();

                    totalRecords = sortedResultsDataTable.Rows.Count;

                    Console.WriteLine($"\nTotal Matches Found:  {totalRecords}");

                    if (fileOutputFullPath == "-1")
                    {
                        SendOutputToScreen(resultsDataTable: sortedResultsDataTable);
                    }
                    else 
                    {
                        SendOutputToFile(fileFullPath: fileFullPath, fileOutputFullPath: fileOutputFullPath, resultsDataTable: sortedResultsDataTable);
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
        /// <param name="fileFullPath">Full path of the file from which the additional attribute data is displayed</param>
        private static void GetMoreFileDetails(string fileFullPath)
        {
            LocalFile localFile = new(fileFullPath);
            Console.WriteLine("\nFile Attributes --------------------------------------------------------------------------------");
            Console.WriteLine("{0,-15} {1,-64}", "File Name:", localFile.Name);
            Console.WriteLine("{0,-15} {1,-64}", "File Size:", localFile.FileSize + " bytes");
            Console.WriteLine("{0,-15} {1,-64}", "Created Date:", localFile.CreatedDate);
            Console.WriteLine("{0,-15} {1,-64}", "Accessed Date:", localFile.LastAccessed);
            Console.WriteLine("{0,-15} {1,-64}", "Modified Date:", localFile.LastModifiedDate);
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }

        /// <summary>
        /// Returns all starting indices/indexes (zero based) of a specified hexadecimal value that was located within a larger hexadecimal string
        /// </summary>
        /// <param name="searchHex">Hexadecimal value to be searched for</param>
        /// <param name="fullHex">Full hexadecimal string to be searched</param>
        /// <returns>Starting indices (zero based) of a specified hexadecimal value</returns>
        private static IEnumerable Offetlocations(string searchHex, string fullHex)
        {
            int searchPos = 0;
            int retVal = fullHex.IndexOf(searchHex, searchPos);
            while (retVal != -1)
            {
                yield return retVal;
                searchPos = retVal + searchHex.Length;
                retVal = fullHex.IndexOf(searchHex, searchPos);
            }
        }

        /// <summary>
        /// Returns a hexadecimal sequence that starts at a specified offset and ends at a specified byte length
        /// </summary>
        /// <param name="fileFullPath">Full path of the file from which the hexadecimal values are read</param>
        /// <param name="startingHexOffSet">Hexadecimal offset from which to start reading</param>
        /// <param name="lengthToRead">Byte length to read</param>
        /// <returns>Hexadecimal value at the specified offset and length</returns>
        private static string ReadCustomByteRange(string fileFullPath, int startingHexOffSet, int lengthToRead) 
        {
            byte[] bytesFile = new byte[lengthToRead];

            using (FileStream fs = File.OpenRead(fileFullPath))
            {
                fs.Position = startingHexOffSet; 
                fs.Read(bytesFile, 0, lengthToRead);
                fs.Close();
            }
            return BitConverter.ToString(bytesFile).Replace("-", "");
        }

        /// <summary>
        /// Patch a specified file with a selected hexadecimal sequence from the signatures.json file
        /// </summary>
        /// <param name="fileFullPath">Full path of the file in which the hexadecimal values will be patched</param>
        /// <param name="searchId">ID associated with a specific file type's attributes, offset and hexadecimal sequence that is located within the signatures.json file</param>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        public static void PatchBytes(string fileFullPath, int searchId, in List<Signature> signatureList) 
        {
            try
            {
                string revertByte = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: signatureList[searchId - 1].Offset,
                lengthToRead: Convert.FromHexString(signatureList[searchId - 1].Hex).Length);
                WriteFSRHeader("Patch byte/s (File Signature ID Association)");
                Console.WriteLine($"\nEnsure you have backed up file {fileFullPath}");
                Console.Write($"Confirm:  Write '{signatureList[searchId - 1].Hex}' (base 16) byte values matching extension '{signatureList[searchId - 1].Name}' " 
                    + $"starting at Offset '{String.Format("0x{0:X}", signatureList[searchId - 1].Offset)}' (type y or n):"); 
                if (Console.ReadKey().Key == ConsoleKey.Y)
                {
                    using FileStream fs = File.OpenWrite(fileFullPath);

                    fs.Position = signatureList[searchId - 1].Offset; 
                    var data = signatureList[searchId - 1].Hex;
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' (base 16) byte values starting at offset {String.Format("0x{0:X}", signatureList[searchId - 1].Offset)} to revert back to the original byte sequence"); 
                    Console.WriteLine($"Command: -pc \"{fileFullPath}\" \"{revertByte}\" \"{String.Format("0x{0:X}", signatureList[searchId - 1].Offset)}\""); 
                }
                else
                {
                    Environment.Exit(0);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Patch a specified file with a custom hexadecimal sequence at a specified starting offset
        /// </summary>
        /// <param name="fileFullPath">Full path of the file in which the hexadecimal values will be patched</param>
        /// <param name="hexSequence">Custom hexadecimal sequence to patch</param>
        /// <param name="startingHexOffSet">Hexadecimal offset from which to start patching</param>
        public static void PatchBytesCustomRange(string fileFullPath, string hexSequence, string startingHexOffSet) 
        {
            try
            {
                string revertByte = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: Convert.ToInt32(startingHexOffSet, 16),
                    lengthToRead: Convert.FromHexString(hexSequence.Replace("0x", "").Replace(" ", "")).Length);

                WriteFSRHeader("Patch byte/s (Custom byte/s sequence)");
                Console.WriteLine($"\nEnsure you have backed up file {fileFullPath}");
                Console.Write($"Confirm:  Write '{hexSequence}' (base 16) byte values starting at Offset '{String.Format("0x{0:X}", Convert.ToInt32(startingHexOffSet, 16))}' (type y or n):");
                if (Console.ReadKey().Key == ConsoleKey.Y)
                {
                    using FileStream fs = File.OpenWrite(fileFullPath);
                    fs.Position = Convert.ToInt32(startingHexOffSet, 16); 
                    var data = hexSequence.Replace("0x", "").Replace(" ", "");
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' (base 16) byte values starting at offset {String.Format("0x{0:X}", Convert.ToInt32(startingHexOffSet, 16))} to revert back to the original byte sequence"); 
                    Console.WriteLine($"Command: -pc \"{fileFullPath}\" \"{revertByte}\" \"{String.Format("0x{0:X}", Convert.ToInt32(startingHexOffSet, 16))}\"");
                }
                else
                {
                    Environment.Exit(0);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Carve bytes from a specified file wihtin a specific hexadecimal offset range and write output to a new file
        /// </summary>
        /// <param name="fileFullPath">Full path of the file from which the hexadecimal byte values will be carved</param>
        /// <param name="startingHexOffSet">Hexadecimal offset that represents the start of the byte carving offset range</param>
        /// <param name="endingHexOffSet">Hexadecimal offset that represents the end of the byte carving offset range</param>
        /// <param name="fileOutputFullPath">Full path of the file to which the results will be written</param>
        public static void ByteCarverByOffsets(string fileFullPath, string startingHexOffSet, string endingHexOffSet, string fileOutputFullPath) 
        {
            try
            {
                int customSize = Convert.ToInt32(endingHexOffSet, 16) - Convert.ToInt32(startingHexOffSet, 16);
                byte[] buffer = new byte[customSize];

                WriteFSRHeader("Carve byte/s sequence");
                using FileStream fs = File.OpenRead(fileFullPath);
                fs.Position = Convert.ToInt32(startingHexOffSet, 16); 
                fs.Read(buffer, 0, customSize);
                using FileStream fs1 = File.OpenWrite(fileOutputFullPath);
                {
                    fs1.Write(buffer, 0, buffer.Length);
                    fs1.Close();
                }
                fs.Close();
                Console.WriteLine($"\nOutput successfully written to {fileOutputFullPath}!!!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a string that represents the first few lines that are written to the windows console
        /// </summary>
        /// <param name="moduleName">Represents the name of 'FILE SIGNATURE RESOLVER v1.0  (BETA)' command module that was executed</param>
        public static void WriteFSRHeader(string moduleName)
        {
            Console.WriteLine("\n------------------------------------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine("-------------------------                              FILE SIGNATURE RESOLVER v1.0  (BETA)                                ---------------------");
            Console.WriteLine("-------------------------                                                    with added patching/carving/hashing features  ---------------------");
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
            Console.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
            Console.WriteLine($"\nModule:  {moduleName}");
        }

        /// <summary>
        /// Returns a complete list of known file signatures from the signatures.json file
        /// </summary>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        public static void DisplayHeaders(in List<Signature> signatureList)
        {
            try
            {
                WriteFSRHeader("Display Existing File Signatures");
                Console.WriteLine($"\nTotal File Signatures:  {signatureList.Count}");
                foreach (Signature signatureRow in signatureList)
                {
                    Console.WriteLine("\n{0,-20} {1,-120}", "ID:", signatureRow.Id);
                    Console.WriteLine("{0,-20} {1,-120}", "Extension:", signatureRow.Name);
                    Console.WriteLine("{0,-20} {1,-120}", "Offset:", signatureRow.Offset + " (base 10) / " + String.Format("0x{0:X}",Convert.ToInt32(signatureRow.Offset)) + " (base 16)");
                    Console.WriteLine("{0,-20} {1,-120}", "Value at offset:", signatureRow.Hex + " (base 16) ");
                    Console.WriteLine("{0,-20} {1,-120}", "ASCII:", FileOperations.HexToAscii(HexString: signatureRow.Hex));
                    Console.WriteLine("{0,-20} {1,-120}", "MIME:", signatureRow.Mime);
                    Console.WriteLine("\n---------------------------------------------");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a list of file signatures, from the extensions.json file, in which the specified file extension is contained within the JSON extension key/value pair
        /// </summary>
        /// <param name="searchExtKeyWord">File extension to be searched</param>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        public static void DisplayHeadersSearchByExtension(string searchExtKeyWord, in List<Signature> signatureList)
        {
            try
            {
                int signature1 = signatureList.FindAll(x => x.Name.ToLower().Contains(searchExtKeyWord.ToLower())).Count;
                if (signature1 > 0)
                {
                    WriteFSRHeader($"Display Existing File Signatures (Matched where extension '{searchExtKeyWord}' is contained within the known 'Extension' values)");
                    Console.WriteLine($"\nTotal File Signatures:  {signature1}");
                    foreach (Signature tempSignature in signatureList.FindAll(x => (x.Name.ToLower().Contains(searchExtKeyWord.ToLower())))) 
                    {
                        Console.WriteLine("\n{0,-20} {1,-120}", "ID:", tempSignature.Id);
                        Console.WriteLine("{0,-20} {1,-120}", "Extension:", tempSignature.Name);
                        Console.WriteLine("{0,-20} {1,-120}", "Offset:", tempSignature.Offset + " (base 10) / " + String.Format("0x{0:X}", Convert.ToInt32(tempSignature.Offset)) + " (base 16)");
                        Console.WriteLine("{0,-20} {1,-120}", "Value at offset:", tempSignature.Hex + " (base 16) ");
                        Console.WriteLine("{0,-20} {1,-120}", "ASCII:", FileOperations.HexToAscii(HexString: tempSignature.Hex));
                        Console.WriteLine("{0,-20} {1,-120}", "MIME:", tempSignature.Mime);
                        Console.WriteLine("\n---------------------------------------------");
                    }
                }
                else { Console.WriteLine($"\nNo matching records were found for extension:  {searchExtKeyWord}"); }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Remove hex identifiers and spaces from the hex string to be searched
        /// </summary>
        /// <param name="searchHexKeyWord">File header (hexadecimal value) to be searched</param>
        private static void SanitizeHex(ref string searchHexKeyWord)
        {
            if (searchHexKeyWord.Contains("0x", StringComparison.CurrentCulture))
            {
                string formattedHexKeyWord = string.Empty;
                string[] testStr = searchHexKeyWord.Split("0x", StringSplitOptions.RemoveEmptyEntries);
                foreach (string testStr2 in testStr)
                {
                    formattedHexKeyWord += testStr2;
                }
                searchHexKeyWord = formattedHexKeyWord.Replace(" ", ""); //cater for residual spaces
            }
            else if (searchHexKeyWord.Contains(' ', StringComparison.CurrentCulture))
            {
                searchHexKeyWord = searchHexKeyWord.Replace(" ", ""); 
            }
        }

        /// <summary>
        /// Returns a list of file signatures, from the extensions.json file, in which the specified byte sequence is contained within the related JSON signature (signs) key/value pair
        /// </summary>
        /// <param name="searchHexKeyWord">File header (hexadecimal value) to be searched</param>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        public static void DisplayHeadersSearchByHex(string searchHexKeyWord, in List<Signature> signatureList)
        {
            try
            {
                SanitizeHex(ref searchHexKeyWord);
                int signature1 = signatureList.FindAll(x => x.Hex.ToLower().Contains(searchHexKeyWord.ToLower())).Count;

                if (signature1 > 0)
                {
                    WriteFSRHeader($"Display Existing File Signatures (Matched where byte sequence '{searchHexKeyWord}' is contained within the known values at the required offset)");
                    Console.WriteLine($"\nTotal File Signatures:  {signature1}");
                    foreach (Signature tempSignature in signatureList.FindAll(x => (x.Hex.ToLower().Contains(searchHexKeyWord.ToLower())))) 
                    {
                        Console.WriteLine("\n{0,-20} {1,-120}", "ID:", tempSignature.Id);
                        Console.WriteLine("{0,-20} {1,-120}", "Extension:", tempSignature.Name);
                        Console.WriteLine("{0,-20} {1,-120}", "Offset:", tempSignature.Offset + " (base 10) / " + String.Format("0x{0:X}", Convert.ToInt32(tempSignature.Offset)) + " (base 16)");
                        Console.WriteLine("{0,-20} {1,-120}", "Value at offset:", tempSignature.Hex + " (base 16) ");
                        Console.WriteLine("{0,-20} {1,-120}", "ASCII:", FileOperations.HexToAscii(HexString: tempSignature.Hex));
                        Console.WriteLine("{0,-20} {1,-120}", "MIME:", tempSignature.Mime);
                        Console.WriteLine("\n---------------------------------------------");
                    }
                    Console.WriteLine("----------------------------------------------------------------------------------------------");
                }
                else { Console.WriteLine($"\nNo matching records were found for hex string:  {searchHexKeyWord}"); }             
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a file hash of a specified file
        /// </summary>
        /// <param name="fileFullPath">Full path of the file to hash</param>
        /// <param name="hashType">Hashing algorithm to implement.  Options include:  MD5, SHA1, SHA256, SHA384, and SHA512</param>
        public static void DisplayFileHash(string fileFullPath, string hashType)
        {
            try
            {
                LocalFile localFile = new(fileFullPath);
                WriteFSRHeader("Display file hash");
                Console.WriteLine("\n{0,-15} {1,-64}", "Hash Type", "Hash Value");
                switch (hashType.ToUpper())
                {
                    case nameof(HashType.MD5):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.MD5), localFile.GetMD5Hash());
                        break;
                    case nameof(HashType.SHA1):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA1), localFile.GetSHA1Hash());
                        break;
                    case nameof(HashType.SHA256):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA256), localFile.GetSHA256Hash());
                        break;
                    case nameof(HashType.SHA384):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA384), localFile.GetSHA384Hash());
                        break;
                    case nameof(HashType.SHA512):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA512), localFile.GetSHA512Hash());
                        break;
                    case nameof(HashType.ALL):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.MD5), localFile.GetMD5Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA1), localFile.GetSHA1Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA256), localFile.GetSHA256Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA384), localFile.GetSHA384Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA512), localFile.GetSHA512Hash());
                        break;
                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }

        }
    }
}
