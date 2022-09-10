
using System;
using System.Data;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;
using fh_res;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


//Declare full path to signature JSON file
//JSON retrieved from https://github.com/qti3e renamed file to signatures.json
string signatureFilePath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\signatures.json";
//update
//Declare list type signature into which the magic contents will be loaded
List<Signature> signature = new();

//Load magic text contents into signature object
LoadJson(signatureFilePath, ref signature); //ref used as it can be modified
GetFileType("C:\\Users\\Admin\\Documents\\Win10_1703_English_x64.iso", in signature); //in is cannot be changed
//DisplayHeaders_SearchByExtension("lha", ref signature); //id 16 has na offset of 2
//PatchBytes("C:\\Users\\Admin\\Desktop\\text.xlsx", "16", ref signature);
//PatchBytesCustomRange("C:\\Users\\Admin\\Desktop\\text.xlsx", "030414", "160");
//ReadCustomByteRange("C:\\Users\\Admin\\Desktop\\text.xlsx", "2", "3");
//ReadBytes("C:\\Users\\Admin\\Desktop\\text.xlsx", "384", "19");
//ReadCustomByteRange_Offset("C:\\Users\\Admin\\Desktop\\text.xlsx", "0x180", "0x193", "C:\\Users\\Admin\\Desktop\\rcro1.txt");

switch (args[0])
{
    case "-h":
        Console.WriteLine("\n------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("-------------------------                                 FILE HEADER RESOLVER v1.0  (BETA)                                ---------------------");
        Console.WriteLine("-------------------------                                                    with added patching features                  ---------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
        Console.WriteLine("\n{0,-25} {1,-60} {2,-50}", "Command/s", "Usage", "Notes");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh (display header)", "-dh", "Return all stored headers");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh --search-ext", "-dh --search-ext \"keyword\"", "Case-insensitive search");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Contained within search e.g. \"if\" returns GIF");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh --search-hex", "-dh --search-hex \"hex value\\s\"", "Must NOT be space seperated e.g. \"4D5A\"");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Case-insensitive search");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Contained within search e.g. \"4D\" returns 42 4D");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"FilePath\"", "Get the file type");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type) --more", "-ft \"FilePath\" --more", "Returns additional file information such as:");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "basic file attributes including the MD5, SHA1,");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "SHA256, SHA384 and SHA512 hashes");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pb (patch byte/s)", "-pb \"FilePath\" \"FileIndex\"", "Patch the header at offset specified in JSON file");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Use the -dh command to get the file index");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "NOTE:  Use at your own risk.  Always backup files first.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pc (patch custom)", "-pc \"FilePath\" \"hex value\\s\" \"offset\"", "Apply custom patch starting at specified offset");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "NOTE:  Use at your own risk.  Always backup files first.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-cb (carve byte/s)", "-cb \"FilePath\" \"Start Offset\" \"End Offset\" \"NewFilePath\"", "Carve out bytes from file and save ouput to a new file.");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        break;
    case "-ft"://-------------------------------------
        if (args.Length == 1)
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -ft \"FilePath\"");
        }
        else if (args.Length == 2)
        {
            if (File.Exists(args[1]))
            {
                //Display File Type
                GetFileType(args[1], in signature); //arg[1]:  File path to get type of, arg[2]:  list of headers //in used as must not be modified
            }
            else
            {
                Console.WriteLine("Error:  File not Found!!!");
                Console.WriteLine("Usage:  -ft \"FilePath\"");
            }
        }
        else if (args.Length == 3)
        {
            if (args[2] == "--more")
            {
                if (File.Exists(args[1]))
                {
                    //Display File Type
                    GetFileType(args[1], in signature); //arg[1]:  File path to get type of, arg[2]:  list of headers //in used as must not be modified
                    GetMoreFileDetails(args[1]);
                }
                else
                {
                    Console.WriteLine("Error:  File not Found!!!");
                    Console.WriteLine("Usage:  -ft \"FilePath\" --more");
                }
            }
            else
            {
                Console.WriteLine("Error:  Invalid argument!!!");
                Console.WriteLine("Usage:  -ft \"FilePath\" --more");
            }//Serach by type }
        }
        break;
    case "-pb":
        //Patch the file with the selected header from the header list
        PatchBytes(args[1], args[2], ref signature);//arg[1]:  File path of file to patch, arg[2]:  Index of header to patch with, arg[3]:  list of headers
        break;
    case "-pc": //DONE
        //Patch the file with the selected header from the header list
        PatchBytesCustomRange(args[1], args[2], args[3]);//arg[1]:  File path of file to patch, arg[2]:  Index of header to patch with, arg[3]:  list of headers
        break;
    case "-cb": //DONE
        //Read bytes at offset and return hex and ASCII values
        byteCarver_Offset(args[1], args[2], args[3], args[4]); //arg[1]: FilePath arg[2]: Offset  arg[3]: Length to read
        break;
    case "-dh":
        //Display headers list
        if (args.Length == 1)
        {
            DisplayHeaders(ref signature);//Display all headers
        }
        else if (args.Length == 3)
        {
            if (args[1] == "--search-ext") { DisplayHeaders_SearchByExtension(args[2], ref signature); } //Serach by type }
            else if (args[1] == "--search-hex") { DisplayHeaders_SearchByHex(args[2], ref signature); } //Serach by hex }
        }
        break;
    default:
        Console.WriteLine("Error:  Unknown command!!!");
        Console.WriteLine("Press enter to exit....");
        Console.ReadLine();
        break;
}

static string HexToAscii(string hexValues, int lengthToPrint, bool IgnoreLength) //needs to change
{
    string ascii = string.Empty;
    string hex = String.Empty;

    if (IgnoreLength == true) //hexvalues is a defined length. no need to substring
    {
        hex = hexValues;
    }
    else if (IgnoreLength == false) { hex = hexValues[..lengthToPrint]; } //substring from 0 to lenght

    string[] splitValues = hex.Chunk(2).Select(x => new string(x)).ToArray();

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
/// Patch header from offset 0
/// </summary> 
static void PatchBytes(string args1, string args2, ref List<Signature> signature) //arg1 file arg2 index DONE
{
    int indexTemp = Convert.ToInt32(args2);
  
    string revertByte = ReadCustomByteRange(args1, signature[indexTemp - 1].Offset, Convert.FromHexString(signature[indexTemp - 1].Hex).Length); //last arg converts hex to byte then counts length

    Console.WriteLine($"Ensure you have backep up file {args1}");
    Console.Write($"Confirm:  Write '{signature[indexTemp - 1].Hex}' byte values matching extension '{signature[indexTemp - 1].Name}' starting at Offset '{signature[indexTemp - 1].Offset}' (type y or n):");

    if (Console.ReadKey().Key == ConsoleKey.Y)
    {
        try
        {
            using FileStream fs = File.OpenWrite(args1);

            fs.Position = signature[indexTemp - 1].Offset; //offset JSON IS DECIMAL THIS IS CORRECT ...changed to int64
            var data = signature[indexTemp - 1].Hex;//.Replace(" ", ""); 
            byte[] buffer = Convert.FromHexString(data);
            fs.Write(buffer, 0, buffer.Length);
            Console.WriteLine("\nPatch Applied!!!");
            Console.WriteLine($"Use '{revertByte}' byte values starting at offset {signature[indexTemp - 1].Offset} to revert back to the original byte sequence");
            Console.WriteLine($"Command: -pc \"{args1}\" \"{revertByte}\" \"{signature[indexTemp - 1].Offset}\"");
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nError info:" + ex.Message);
            Console.WriteLine("Press enter to exit....");
            Console.ReadLine();
        }
    }
    else   
    {
        Environment.Exit(0);
    }
}

static void PatchBytesCustomRange(string args1, string args2, string args3) //args1 file args2 hex args3 offset in hex DONE
{
    string revertByte = ReadCustomByteRange(args1, Convert.ToInt32(args3,16), Convert.FromHexString(args2).Length); //last arg converts hex to byte then counts length

    Console.WriteLine($"Ensure you have backep up file {args1}");
    Console.Write($"Confirm:  Write '{args2}' byte values starting at Offset '{args3}' (type y or n):");
    if (Console.ReadKey().Key == ConsoleKey.Y)
    {
        try
        {
            using FileStream fs = File.OpenWrite(args1);

            fs.Position = Convert.ToInt32(args3, 16); //offset WRONG CHECK THE OFFSET IN THE JSON IS IT HEX OR DECIMAL...changed to int64
            var data = args2;//.Replace(" ", ""); 
            byte[] buffer = Convert.FromHexString(data);
            fs.Write(buffer, 0, buffer.Length);
            Console.WriteLine("\nPatch Applied!!!");
            Console.WriteLine($"Use '{revertByte}' byte values starting at offset {args3} to revert back to the original byte sequence");
            Console.WriteLine($"Command: -pc \"{args1}\" \"{revertByte}\" \"{args3}\"");
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nError info:" + ex.Message);
            Console.WriteLine("Press enter to exit....");
            Console.ReadLine();
        }
    }
    else
    {
        Environment.Exit(0);
    }

}

/// <summary>
/// Display headers list
/// </summary>
static void DisplayHeaders(ref List<Signature> signature)
{
    Console.WriteLine("{0,-5} {1,-15} {2,-10} {3,-120} {4,-120} {5,-50}", "ID", "Extension", "Offset", "Signature","ASCII", "Mime");
    foreach (Signature signatureRow in signature)
    { //NOTE name is the extension
        Console.WriteLine("{0,-5} {1,-15} {2,-10} {3,-120} {4,-120} {5,-50}", signatureRow.Id, signatureRow.Name, signatureRow.Offset, signatureRow.Hex, HexToAscii(signatureRow.Hex, signatureRow.Hex.Length, true), signatureRow.Mime);
    }
}

//static void ReadBytes(string args1, string args2, string args3) //args1 file args2 offset args3 length to read
//{
//    string revertByte = ReadCustomByteRange(args1, Convert.ToInt32(args2), Convert.ToInt32(args3)); 
//    Console.WriteLine($"Hex: {revertByte}");
//    Console.WriteLine($"ASCII: {HexToAscii(revertByte, revertByte.Length, true)}");
//}


static void DisplayHeaders_SearchByExtension(string keyWord, ref List<Signature> signature)
{ //NOTE name is the extension
    Console.WriteLine("{0,-5} {1,-15} {2,-10} {3,-120} {4,-120} {5,-50}", "ID", "Extension", "Offset", "Signature", "ASCII", "Mime");
    Console.WriteLine("----------------------------------------------------------------------------------------------");
    foreach (Signature tempSignature in signature.FindAll(x => (x.Name.ToLower().Contains(keyWord.ToLower())))) //Convert all input to lowercase for searching
    { 
        Console.WriteLine("{0,-5} {1,-15} {2,-10} {3,-120} {4,-120} {5,-50}", tempSignature.Id, tempSignature.Name, tempSignature.Offset, tempSignature.Hex, HexToAscii(tempSignature.Hex, tempSignature.Hex.Length, true), tempSignature.Mime); //Display only headers that were searched for
    }
    Console.WriteLine("----------------------------------------------------------------------------------------------");
}

static void DisplayHeaders_SearchByHex(string keyWord, ref List<Signature> signature)
{
    Console.WriteLine("{0,-5} {1,-15} {2,-10} {3,-120} {4,-120} {5,-50}", "ID", "Extension", "Offset", "Signature", "ASCII", "Mime");
    Console.WriteLine("----------------------------------------------------------------------------------------------");
    foreach (Signature tempSignature in signature.FindAll(x => (x.Hex.ToLower().Contains(keyWord.ToLower())))) //Convert all input to lowercase for searching
    {
        Console.WriteLine("{0,-5} {1,-15} {2,-10} {3,-120} {4,-120} {5,-50}", tempSignature.Id, tempSignature.Name, tempSignature.Offset, tempSignature.Hex, HexToAscii(tempSignature.Hex, tempSignature.Hex.Length, true), tempSignature.Mime); //Display only headers that were searched for
    }
    Console.WriteLine("----------------------------------------------------------------------------------------------");
}

static void GetMoreFileDetails(string fullPath)
{
    LocalFile localFile = new LocalFile(fullPath);
    Console.WriteLine("\n----------------------------------------------------------------------------------------------");
    Console.WriteLine("----------                   ADDITIONAL DETAILS                                   ------------");
    Console.WriteLine("----------------------------------------------------------------------------------------------");
    Console.WriteLine("{0,-15} {1,-64}", "File Name:" , localFile.Name);
    Console.WriteLine("{0,-15} {1,-64}", "File Size:" , localFile.FileSize + " bytes");
    Console.WriteLine("{0,-15} {1,-64}", "Created Date:" , localFile.CreatedDate );
    Console.WriteLine("{0,-15} {1,-64}", "Accessed Date:" , localFile.LastAccessed );
    Console.WriteLine("{0,-15} {1,-64}", "Modified Date:", localFile.LastModifiedDate );
    Console.WriteLine("{0,-15} {1,-64}", "MD5:", localFile.MD5HashValue);
    Console.WriteLine("{0,-15} {1,-64}", "SHA1:" , localFile.Sha1HashValue);
    Console.WriteLine("{0,-15} {1,-64}", "SHA256:" , localFile.Sha256HashValue);
    Console.WriteLine("{0,-15} {1,-64}", "SHA384:" , localFile.Sha384HashValue);
    Console.WriteLine("{0,-15} {1,-64}", "SHA512:" , localFile.Sha512HashValue);
    Console.WriteLine("----------------------------------------------------------------------------------------------");
}

static string ReadCustomByteRange(string filePath, int offSet, int lengthToRead) //args1 file args2 offset args3 length to read
{
    int customSize = lengthToRead; 
    byte[] bytesFile = new byte[customSize];

    using (FileStream fs = File.OpenRead(filePath))//@argFilePath
    {
        fs.Position = offSet; //offset to read from
        fs.Read(bytesFile, 0, customSize);
        fs.Close();
    }

    return BitConverter.ToString(bytesFile).Replace("-", "");  
}

static void byteCarver_Offset(string filePath, string startingOffSet, string endingOffSet, string newFilePath) //args1 file args2 offset args3 length to read
{
    int customSize = Convert.ToInt32(endingOffSet, 16) - Convert.ToInt32(startingOffSet, 16);
    byte[] buffer = new byte[customSize];

    using (FileStream fs = File.OpenRead(filePath))//@argFilePath
    {
        fs.Position = Convert.ToInt32(startingOffSet, 16); //offset to read from
        fs.Read(buffer, 0, customSize);
        using FileStream fs1 = File.OpenWrite(newFilePath);
        {
            fs1.Write(buffer, 0, buffer.Length);
            fs1.Close();
        }
        fs.Close();
    }
}

/// <summary>
/// Display File Type
/// </summary>
static void GetFileType(string args1, in List<Signature> signature)
{
    int headerSize = signature.Max(t=>t.Offset) + 1; //read 1 byte passed the end
    byte[] bytesFile = new byte[headerSize];

    using (FileStream fs = File.OpenRead(args1))//@argFilePath
    {
        fs.Read(bytesFile, 0, headerSize); //read header into bytesfile
        fs.Close();
    }

    string header = BitConverter.ToString(bytesFile).Replace("-", "");  //Convert the byte file to its hex string representation and remove the - symbols
    Console.WriteLine("\n----------------------------------------------------------------------------------------------");
    Console.WriteLine("----------                            FILE TYPE                                   ------------");
    Console.WriteLine("----------------------------------------------------------------------------------------------");

    try
    {
        int columnCount = 7;
        var query = signature.Where(x => header.Contains(x.Hex)); //get all rows where JSON signature matches with a byte sequence in the header

        Console.WriteLine($"\nFile:  {args1}");
        Console.WriteLine($"Total Matches Found:  {query.Count()}");

        string[,] stagingOuput = new string[query.Count(), columnCount];
        DataTable dataTable = new DataTable();
        DataColumn dataColumn;

        for (int i = 0; i <= columnCount-1; i++)
        {
            dataColumn = new DataColumn();
            dataColumn.ColumnName = "Col" + i;
            dataTable.Columns.Add(dataColumn);
        }

        foreach (Signature sig in query)
        {
            string valueAtOffset = ReadCustomByteRange(args1, sig.Offset, Convert.FromHexString(sig.Hex).Length); //get value at expected offset
            var query1 = signature.Where(x => x.Offset == sig.Offset && x.Hex == valueAtOffset && x.Name == sig.Name); //compare above value to hex value in JSON
            dataTable.Rows.Add(new object[] { query1.Any() ? "high" : "low", sig.Name, sig.Offset.ToString(), sig.Hex, 
                HexToAscii(sig.Hex, sig.Hex.Length, true), valueAtOffset, HexToAscii(valueAtOffset, valueAtOffset.Length, true) });//add results to datatable based on above query
        }

        // sort by first column:
        dataTable.DefaultView.Sort = "Col0";
        dataTable = dataTable.DefaultView.ToTable();

        foreach (DataRow dRow in dataTable.Rows)  
        {
            Console.WriteLine("\n{0,-30} {1,-64}", "Probability", dRow[0].ToString());
            Console.WriteLine("{0,-30} {1,-64}", "Extension (JSON):", dRow[1].ToString());
            Console.WriteLine("{0,-30} {1,-64}", "Offset (JSON):", dRow[2].ToString()); //Hexadecimal (JSON)
            Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal (JSON):", dRow[3].ToString());
            Console.WriteLine("{0,-30} {1,-64}", "ASCII (JSON):", dRow[4].ToString());
            Console.WriteLine("{0,-30} {1,-64}", "Value at Offset " + dRow[2].ToString() + ":", dRow[5].ToString());
            Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal at Offset " + dRow[2].ToString() + ":", dRow[6].ToString());
        }
    }
    catch (InvalidOperationException)
    {
        Console.WriteLine("Cannot find exact matching header!!!");
        Console.WriteLine("Current Header Information: (Displaying 16 bytes from offset 0)"); //catered for 4 spaces conatined in the header variable
        Console.WriteLine("{0,-15} {1,-64}", "Hexadecimal:", header[..20]); //this is wrong
        Console.WriteLine("{0,-15} {1,-64}", "ASCII:", HexToAscii(header, 20, false)); //this is wrong
    }
    catch (Exception ex)
    {
        Console.WriteLine("Error info:" + ex.Message);
        Console.WriteLine("Press enter to exit....");
        Console.ReadLine();
    }
    finally
    {
        Console.WriteLine("----------------------------------------------------------------------------------------------");
    }
}

static void LoadJson(string signatureListFilePath, ref List<Signature> signatureList)
{
    List<StagingSignature> stagingSignature = new();

    using (StreamReader r = new(signatureListFilePath))
    {
        string json = r.ReadToEnd(); //read the JSON file
        var jo = JObject.Parse(json); //initialise an object to iterate through the nodes

        foreach (var kv in jo)
        {
            if (kv.Value!=null)
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
                string hexValue = val.Substring(val.IndexOf(',')+1); //substring(2)
                signatureList.Add(new Signature() { Id = stagingCounter, Name = signs.Name, Offset = offset, Hex  = hexValue, Mime = signs.Mime });
                stagingCounter++;
            }
        }

        r.Close();
    }





}
