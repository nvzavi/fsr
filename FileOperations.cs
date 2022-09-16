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
                string json = r.ReadToEnd(); //read the JSON file
                var jo = JObject.Parse(json); //initialise an object to iterate through the nodes

                foreach (var kv in jo)
                {
                    if (kv.Value != null)
                    {
                        var deserializable = kv.Value.ToString(); //get deserializable children

                        if (kv.Key != null) //Get the Name.  Name is the root node e.g. 123
                        {
                            var sign = JsonConvert.DeserializeObject<StagingSignature>(deserializable);
                            sign.Name = kv.Key;
                            stagingSignature.Add(sign);//deserialise each node and add to signature object
                        }
                    }
                }

                int stagingCounter = 1;
                foreach (StagingSignature signs in stagingSignature)
                {

                    foreach (var val in signs.Signs) //access signature list attribute
                    {
                        int offset = Convert.ToInt32(val[..val.IndexOf(',')]); //substring(0,1)
                        string hexValue = val[(val.IndexOf(',') + 1)..]; //substring(2) old string hexValue = val.Substring(val.IndexOf(',') + 1);
                        signatureList.Add(new Signature()
                        {
                            Id = stagingCounter,
                            Name = signs.Name,
                            Offset = offset,
                            Hex = hexValue,
                            Mime = signs.Mime
                        });
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

            if (lengthOfHexString != 0) { HexString = HexString[..lengthOfHexString]; } //substring from 0 to lenght

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

            int columnCount = 9;

            for (int i = 0; i <= columnCount - 1; i++)
            {
                dataColumn = new DataColumn();
                dataColumn.ColumnName = "Col" + i;
                processedDataTable.Columns.Add(dataColumn);
            }

            foreach (Signature sig in signatureQuery) //loop through all matched records and update datatable with additional attributes locatedPos
            {
                //get the current offset within the byte sequence
                string locatedPos = string.Empty;
                int posCounter = 0;
                int posValue = 0;

                foreach (var offsetLoc in Offetlocations(searchHex: sig.Hex, fullHex: hexString))
                {
                    if (Convert.ToInt32(offsetLoc) % 2 != 0) //if its not an even number then skip execution and proceed to next iteration :  hex found at even number only
                    {
                        continue;
                    }
                    posValue = Convert.ToInt32(offsetLoc) / 2; //divide by 2 to get the byte value
                    string tempOutput = posValue == sig.Offset ? String.Format("0x{0:X}", Convert.ToInt32(offsetLoc) / 2) + " <--match" : String.Format("0x{0:X}",
                        Convert.ToInt32(offsetLoc) / 2); //assign match string to matched offset

                    if (posCounter == 0)
                    {
                        locatedPos = tempOutput.ToString(); //for the first output return only tempOutput  String.Format("0x{0:X}", Convert.ToInt32(tempOutput));
                    }
                    else if (posCounter <= 5)
                    {
                        locatedPos = locatedPos + " / " + tempOutput.ToString(); //for every tempOutput where the count is <6, add a trailing slash (/) 
                    }
                    else
                    {
                        locatedPos += " ***"; //if count is >= 6 then insert *** to denote multiple occurences of offset in several offsets 
                        break;
                    }
                    posCounter++;
                }

                string hexValueAtOffset = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: sig.Offset, lengthToRead: Convert.FromHexString(sig.Hex).Length); //get value at expected offset
                var queryResultsToAdd = signatureList.Where(x => x.Offset == sig.Offset && x.Hex == hexValueAtOffset && x.Name == sig.Name); //compare above value to hex value in JSON
                processedDataTable.Rows.Add(new object[] { queryResultsToAdd.Any() ? "high" : "low",
                                                sig.Name,
                                                sig.Offset.ToString(),
                                                sig.Hex,
                                                FileOperations.HexToAscii(HexString: sig.Hex),
                                                sig.Mime,
                                                hexValueAtOffset,
                                                FileOperations.HexToAscii(HexString: hexValueAtOffset),
                                                locatedPos });//add results to datatable based on above query
            }

            // sort by first column:
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
                    Convert.ToInt32(dRow[2])) + "(base 16)"); //show output in decimal and hex
                Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal (expected):", dRow[3].ToString());
                Console.WriteLine("{0,-30} {1,-64}", "ASCII (expected):", dRow[4].ToString());
                Console.WriteLine("{0,-30} {1,-64}", "Mime:", dRow[5].ToString()); //added mime

                if (dRow[0].ToString() == "low")
                {
                    Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal at Offset " + dRow[2].ToString() + ":", dRow[6].ToString());
                    Console.WriteLine("{0,-30} {1,-64}", "ASCII at Offset " + dRow[2].ToString() + ":", dRow[7].ToString());

                }

                Console.WriteLine("{0,-30} {1,-64}", "Located Offset\\s:", dRow[8].ToString());
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
            sw.WriteLine("----------------------------------------------------------------------------------------------");
            sw.WriteLine("----------                            FILE TYPE                                   ------------");
            sw.WriteLine("----------------------------------------------------------------------------------------------");
            sw.WriteLine("Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");
            sw.WriteLine("");
            sw.WriteLine($"File:  {fileFullPath}");
            sw.WriteLine($"Processed Date:  {DateTime.Now}");
            sw.WriteLine($"Total Matches Found:  {resultsDataTable.Rows.Count}");
            sw.WriteLine("");
            // Add some text to file    
            foreach (DataRow dRow in resultsDataTable.Rows)
            {
                sw.WriteLine("{0,-30} {1,-64}", "Probability:", dRow[0].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "Extension:", dRow[1].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "Offset (expected):", dRow[2].ToString() + " (base 10) - " + String.Format("0x{0:X}",
                    Convert.ToInt32(dRow[2])) + "(base 16)"); //show output in decimal and hex
                sw.WriteLine("{0,-30} {1,-64}", "Hexadecimal (expected):", dRow[3].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "ASCII (expected):", dRow[4].ToString());
                sw.WriteLine("{0,-30} {1,-64}", "Mime:", dRow[5].ToString()); //added mime

                if (dRow[0].ToString() == "low")
                {
                    sw.WriteLine("{0,-30} {1,-64}", "Hexadecimal at Offset:" + dRow[2].ToString() + ":", dRow[6].ToString());
                    sw.WriteLine("{0,-30} {1,-64}", "ASCII at Offset:" + dRow[2].ToString() + ":", dRow[7].ToString());

                }

                sw.WriteLine("{0,-30} {1,-64}", "Located Offset\\s:", dRow[8].ToString());
                sw.WriteLine("");
                sw.WriteLine("");
            }
            Console.WriteLine("Output written to file: " + fileOutputFullPath);

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
        public static void GetFileType(string fileFullPath, in List<Signature> signatureList, string fileOutputFullPath = "-1") //fileOutputFullPath is optional
        {
            string fullHexString = String.Empty;
            //Validate fileFullPath and fileOutputFullPath arguments
            try 
            {
                if (!File.Exists(path: fileFullPath)) //this arg will must always exist
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
                        // Change fileOutputFullPath to new name
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

                using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
                {
                    byteSize = (int)fs.Length; //possible loss of data here FIX IT
                    bytesFile = new byte[byteSize];
                    fs.Read(bytesFile, 0, byteSize); //read header into bytesfile
                    fs.Close();
                }

                fullHexString = BitConverter.ToString(bytesFile).Replace("-", "");  //Convert the byte file to its hex string representation and remove the - symbols
                Console.WriteLine("\n----------------------------------------------------------------------------------------------");
                Console.WriteLine("----------                            FILE TYPE                                   ------------");
                Console.WriteLine("----------------------------------------------------------------------------------------------");
                Console.WriteLine("Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");

                var queryResult = signatureList.Where(x => fullHexString.Contains(x.Hex)); //get all rows where JSON signature matches with a byte sequence in the file

                Console.WriteLine($"\nFile:  {fileFullPath}");
                GetMoreFileDetails(fileFullPath: fileFullPath);

                int totalRecords = queryResult.Count();
                Console.WriteLine($"\nTotal Matches Found:  {totalRecords}");
                if (totalRecords > 0)
                {
                    //Process query results and sort the results from high to low probability
                    DataTable sortedResultsDataTable;
                    sortedResultsDataTable = FetchResultsSortedAsc(signatureQuery: queryResult, hexString: fullHexString, fileFullPath: fileFullPath, signatureList: in signatureList).Copy();
                    //write output to file
                    if (fileOutputFullPath == "-1") //output to screen
                    {
                        SendOutputToScreen(resultsDataTable: sortedResultsDataTable);
                    }
                    else //output to file
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
                fs.Position = startingHexOffSet; //offset to read from
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
                lengthToRead: Convert.FromHexString(signatureList[searchId - 1].Hex).Length); //last arg converts hex to byte then counts length FIX FromHexString see custompatch void
                Console.WriteLine($"Ensure you have backep up file {fileFullPath}");
                Console.Write($"Confirm:  Write '{signatureList[searchId - 1].Hex}' byte values matching extension '{signatureList[searchId - 1].Name}' " +
                    $"starting at Offset '{signatureList[searchId - 1].Offset}' (type y or n):");

                if (Console.ReadKey().Key == ConsoleKey.Y)
                {
                    using FileStream fs = File.OpenWrite(fileFullPath);

                    fs.Position = signatureList[searchId - 1].Offset; //offset JSON IS DECIMAL THIS IS CORRECT ...changed to int64
                    var data = signatureList[searchId - 1].Hex;//.Replace(" ", ""); 
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' byte values starting at offset {signatureList[searchId - 1].Offset} to revert back to the original byte sequence");
                    Console.WriteLine($"Command: -pc \"{fileFullPath}\" \"{revertByte}\" \"{signatureList[searchId - 1].Offset}\"");
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
                //revertByte is called again and again for different function...look at calling it once
                string revertByte = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: Convert.ToInt32(startingHexOffSet, 16),
                    lengthToRead: Convert.FromHexString(hexSequence.Replace("0x", "").Replace(" ", "")).Length); //last arg converts hex to byte then counts length

                Console.WriteLine($"Ensure you have backep up file {fileFullPath}");
                Console.Write($"Confirm:  Write '{hexSequence}' byte values starting at Offset '{startingHexOffSet}' (type y or n):");
                if (Console.ReadKey().Key == ConsoleKey.Y)
                {
                    using FileStream fs = File.OpenWrite(fileFullPath);

                    fs.Position = Convert.ToInt32(startingHexOffSet, 16); //offset WRONG CHECK THE OFFSET IN THE JSON IS IT HEX OR DECIMAL...changed to int64
                    var data = hexSequence.Replace("0x", "").Replace(" ", "");
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' byte values starting at offset {startingHexOffSet} to revert back to the original byte sequence");
                    Console.WriteLine($"Command: -pc \"{fileFullPath}\" \"{revertByte}\" \"{startingHexOffSet}\"");
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

                using FileStream fs = File.OpenRead(fileFullPath);//@argFilePath
                fs.Position = Convert.ToInt32(startingHexOffSet, 16); //offset to read from
                fs.Read(buffer, 0, customSize);
                using FileStream fs1 = File.OpenWrite(fileOutputFullPath);
                {
                    fs1.Write(buffer, 0, buffer.Length);
                    fs1.Close();
                }
                fs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a complete list of known file signatures from the signatures.json file
        /// </summary>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        public static void DisplayHeaders(in List<Signature> signatureList)
        {
            try
            {
                Console.WriteLine("\n----------------------------------------------------------------------------------------------");
                Console.WriteLine("----------                            FILE HEADERS                                ------------");
                Console.WriteLine("----------------------------------------------------------------------------------------------");
                Console.WriteLine($"\nTotal Records:  {signatureList.Count}");
                foreach (Signature signatureRow in signatureList)
                {
                    Console.WriteLine("\n{0,-15} {1,-120}", "ID:", signatureRow.Id);
                    Console.WriteLine("{0,-15} {1,-120}", "Extension:", signatureRow.Name);
                    Console.WriteLine("{0,-15} {1,-120}", "Offset:", signatureRow.Offset);
                    Console.WriteLine("{0,-15} {1,-120}", "Hex:", signatureRow.Hex);
                    Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(HexString: signatureRow.Hex));
                    Console.WriteLine("{0,-15} {1,-120}", "MIME:", signatureRow.Mime);
                    Console.WriteLine("\n---------------------------------------------");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a list of known file signatures, from the signatures.json file, that are associated with a specified file extension 
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
                    Console.WriteLine("\n----------------------------------------------------------------------------------------------");
                    Console.WriteLine("----------                            FILE HEADERS                                ------------");
                    Console.WriteLine("----------------------------------------------------------------------------------------------");
                    Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
                    Console.WriteLine($"\nTotal Records:  {signature1}");
                    foreach (Signature tempSignature in signatureList.FindAll(x => (x.Name.ToLower().Contains(searchExtKeyWord.ToLower())))) //Convert all input to lowercase for searching
                    {
                        Console.WriteLine("\n{0,-15} {1,-120}", "ID:", tempSignature.Id);
                        Console.WriteLine("{0,-15} {1,-120}", "Extension:", tempSignature.Name);
                        Console.WriteLine("{0,-15} {1,-120}", "Offset:", tempSignature.Offset);
                        Console.WriteLine("{0,-15} {1,-120}", "Hex:", tempSignature.Hex);
                        Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(HexString: tempSignature.Hex));
                        Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
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
        /// Returns a list of known file signatures, from the signatures.json file, that are associated with a specified header (hexadecimal value) 
        /// </summary>
        /// <param name="searchHexKeyWord">File header (hexadecimal value) to be searched</param>
        /// <param name="signatureList">List containing the signatures.json file contents</param>
        public static void DisplayHeadersSearchByHex(string searchHexKeyWord, in List<Signature> signatureList)
        {
            try
            {
                int signature1 = signatureList.FindAll(x => x.Hex.ToLower().Contains(searchHexKeyWord.ToLower())).Count;
                if (signature1 > 0)
                {
                    Console.WriteLine("\n----------------------------------------------------------------------------------------------");
                    Console.WriteLine("----------                            FILE HEADERS                                ------------");
                    Console.WriteLine("----------------------------------------------------------------------------------------------");
                    Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
                    Console.WriteLine($"\nTotal Records:  {signature1}");
                    foreach (Signature tempSignature in signatureList.FindAll(x => (x.Hex.ToLower().Contains(searchHexKeyWord.ToLower())))) //Convert all input to lowercase for searching
                    {
                        Console.WriteLine("\n{0,-15} {1,-120}", "ID:", tempSignature.Id);
                        Console.WriteLine("{0,-15} {1,-120}", "Extension:", tempSignature.Name);
                        Console.WriteLine("{0,-15} {1,-120}", "Offset:", tempSignature.Offset);
                        Console.WriteLine("{0,-15} {1,-120}", "Hex:", tempSignature.Hex);
                        Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(HexString: tempSignature.Hex));
                        Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
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
                Console.WriteLine($"\n{hashType} file hash/s -----------------------------------------------------------------------------");
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
                Console.WriteLine("----------------------------------------------------------------------------------------------");
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }

        }
    }
}
