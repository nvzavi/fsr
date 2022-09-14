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
        public static void LoadJson(string signatureListFilePath, ref List<Signature> signatureList)
        {
            List<StagingSignature> stagingSignature = new();

            using (StreamReader r = new(signatureListFilePath))
            {
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
                        string hexValue = val.Substring(val.IndexOf(',') + 1); //substring(2)
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
        }

        private static string HexToAscii(string HexString, int lengthOfHexString = 0) //needs to change , ignorelength must come out bool IgnoreLength
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

        private static DataTable FetchResultsSortedAsc(IEnumerable<Signature> signatureQuery, string hexString, string fileFullPath, in List<Signature> signatureList)
        {
            DataTable processedDataTable = new DataTable();
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

                foreach (var offsetLoc in Offetlocations(searchTerm: sig.Hex, searchStr: hexString))
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
                        locatedPos = locatedPos + " ***"; //if count is >= 6 then insert *** to denote multiple occurences of offset in several offsets 
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

        private static void SendOutputToFile(string fileFullPath, string fileOutputFullPath, DataTable resultsDataTable)
        {
            using (FileStream fs = new FileStream(fileOutputFullPath, FileMode.Append, FileAccess.Write))
            {
                using (StreamWriter sw = new StreamWriter(fs)) 
                {
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
                            sw.WriteLine("{0,-30} {1,-64}", "Hexadecimal at Offset " + dRow[2].ToString() + ":", dRow[6].ToString());
                            sw.WriteLine("{0,-30} {1,-64}", "ASCII at Offset " + dRow[2].ToString() + ":", dRow[7].ToString());

                        }

                        sw.WriteLine("{0,-30} {1,-64}", "Located Offset\\s:", dRow[8].ToString());
                        sw.WriteLine("");
                        sw.WriteLine("");
                    }
                    Console.WriteLine("Output written to file: " + fileOutputFullPath);
                }
            }
           
        }

        /// <summary>
        /// Display File Type
        /// </summary>
        public static void GetFileType(string fileFullPath, in List<Signature> signatureList, string fileOutputFullPath = "-1") //fileOutputFullPath is optional
        {
            //Validate fileFullPath and fileOutputFullPath arguments
            //start
            if (!File.Exists(path: fileFullPath)) //this arg will must always exist
            {
                Console.WriteLine($"Error:  File '{fileFullPath}' not found!!!");
                Environment.Exit(0);
            }
            if (fileOutputFullPath!="-1")
            {
                try
                {
                    //string fileName = string.Empty;
                    if (File.Exists(fileOutputFullPath))
                    {
                        Random random = new Random();
                        // Change fileOutputFullPath to new name
                        fileOutputFullPath = Path.GetDirectoryName(fileOutputFullPath) + "\\" + Path.GetFileName(fileOutputFullPath).Substring(0, Path.GetFileName(fileOutputFullPath).IndexOf(".")) + "_fhgen_" + random.Next(10000)
                            + Path.GetFileName(fileOutputFullPath).Substring(Path.GetFileName(fileOutputFullPath).IndexOf("."));

                        StreamWriter writer = new(fileOutputFullPath);
                        writer.Close();
                    }
                    else 
                    { 
                        StreamWriter writer = new(fileOutputFullPath);
                        writer.Close();
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"Error:  Access to output path '{fileOutputFullPath}' was denied!!!");
                    Environment.Exit(0);
                }
                catch (DirectoryNotFoundException)
                {
                    Console.WriteLine($"Error:  Output path '{fileOutputFullPath}' was not found!!!");
                    Environment.Exit(0);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error info:" + ex.Message);
                    Environment.Exit(0);
                }
            }
            //end

            byte[] bytesFile;
            using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
            {
                int byteSize = (int)fs.Length; //possible loss of data here FIX IT
                bytesFile = new byte[byteSize];
                fs.Read(bytesFile, 0, byteSize); //read header into bytesfile
                fs.Close();
            }

            string fullHexString = BitConverter.ToString(bytesFile).Replace("-", "");  //Convert the byte file to its hex string representation and remove the - symbols
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE TYPE                                   ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");

            try //
            {
                
                var queryResult = signatureList.Where(x => fullHexString.Contains(x.Hex)); //get all rows where JSON signature matches with a byte sequence in the file

                //add code here to find the original offset if not found at the expected offset

                Console.WriteLine($"\nFile:  {fileFullPath}");
                GetMoreFileDetails(fileFullPath: fileFullPath);

                int totalRecords = queryResult.Count();
                Console.WriteLine($"Total Matches Found:  {totalRecords}");
                //string[,] stagingOuput = new string[query.Count(), columnCount];

                //Process query results and sort the results from high to low probability
                DataTable sortedResultsDataTable;
                sortedResultsDataTable = FetchResultsSortedAsc(signatureQuery: queryResult, hexString: fullHexString, fileFullPath: fileFullPath,signatureList: in signatureList).Copy();
              
                //try catch here
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
            catch (InvalidOperationException)
            {
                Console.WriteLine("Cannot find exact matching byte sequence!!!");
                Console.WriteLine("Current Information: (Displaying 16 bytes from offset 0)"); //catered for 4 spaces conatined in the header variable
                Console.WriteLine("{0,-15} {1,-64}", "Hexadecimal:", fullHexString[..20]); //this is wrong
                Console.WriteLine("{0,-15} {1,-64}", "ASCII:", FileOperations.HexToAscii(HexString: fullHexString, lengthOfHexString: 20)); //this is wrong
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error info:" + ex.Message);
            }
            finally
            {
                Console.WriteLine("----------------------------------------------------------------------------------------------");
            }
        }

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

        private static IEnumerable Offetlocations(string searchTerm, string searchStr)
        {
            int searchPos = 0;
            int retVal = searchStr.IndexOf(searchTerm, searchPos);
            while (retVal != -1)
            {
                yield return retVal;
                searchPos = retVal + searchTerm.Length;
                retVal = searchStr.IndexOf(searchTerm, searchPos);
            }
        }

        private static string ReadCustomByteRange(string fileFullPath, int startingHexOffSet, int lengthToRead) 
        {
            byte[] bytesFile = new byte[lengthToRead];

            using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
            {
                fs.Position = startingHexOffSet; //offset to read from
                fs.Read(bytesFile, 0, lengthToRead);
                fs.Close();
            }
            return BitConverter.ToString(bytesFile).Replace("-", "");
        }

        /// <summary>
        /// Patch header from offset 0
        /// </summary> 
        public static void PatchBytes(string fileFullPath, int searchId, in List<Signature> signatureList) 
        {
            //Validate fileFullPath and searchId arguments
            //start
            if (!File.Exists(path: fileFullPath)) //this arg will must always exist
            {
                Console.WriteLine($"Error:  File '{fileFullPath}' not found!!!");
                Environment.Exit(0);
            }
            if (searchId <= 0) //this arg will must always exist
            {
                Console.WriteLine($"Error:  ID '{searchId}' is not a valid ID!!!\nID must be greater than 0");
                Environment.Exit(0);
            }
            //end

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

        public static void PatchBytesCustomRange(string fileFullPath, string hexSequence, string startingHexOffSet) 
        {
            //Validate fileFullPath argument
            //start
            if (!File.Exists(path: fileFullPath)) //this arg will must always exist
            {
                Console.WriteLine($"Error:  File '{fileFullPath}' not found!!!");
                Environment.Exit(0);
            }
            //end

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

        public static void ByteCarverByOffsets(string fileFullPath, string startingHexOffSet, string endingHexOffSet, string fileOutputFullPath) 
        {
            //Validate fileFullPath argument
            //start
            if (!File.Exists(path: fileFullPath)) //this arg will must always exist
            {
                Console.WriteLine($"Error:  File '{fileFullPath}' not found!!!");
                Environment.Exit(0);
            }
            //end

            try
            {
                int customSize = Convert.ToInt32(endingHexOffSet, 16) - Convert.ToInt32(startingHexOffSet, 16);
                byte[] buffer = new byte[customSize];

                using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
                {
                    fs.Position = Convert.ToInt32(startingHexOffSet, 16); //offset to read from
                    fs.Read(buffer, 0, customSize);
                    using FileStream fs1 = File.OpenWrite(fileOutputFullPath);
                    {
                        fs1.Write(buffer, 0, buffer.Length);
                        fs1.Close();
                    }
                    fs.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Display headers list
        /// </summary>
        public static void DisplayHeaders(in List<Signature> signatureList)
        {
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
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

        public static void DisplayHeadersSearchByExtension(string searchKeyWord, in List<Signature> signatureList)
        {
            int signature1 = signatureList.FindAll(x => x.Name.ToLower().Contains(searchKeyWord.ToLower())).Count;
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature1}");
            foreach (Signature tempSignature in signatureList.FindAll(x => (x.Name.ToLower().Contains(searchKeyWord.ToLower())))) //Convert all input to lowercase for searching
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

        public static void DisplayHeadersSearchByHex(string searchKeyWord, in List<Signature> signatureList)
        {
            int signature1 = signatureList.FindAll(x => x.Hex.ToLower().Contains(searchKeyWord.ToLower())).Count;
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature1}");
            foreach (Signature tempSignature in signatureList.FindAll(x => (x.Hex.ToLower().Contains(searchKeyWord.ToLower())))) //Convert all input to lowercase for searching
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

        public static void DisplayFileHash(string fileFullPath, string hashType)
        {
            LocalFile localFile = new LocalFile(fileFullPath);
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
    }
}
