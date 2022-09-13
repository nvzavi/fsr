
using System;
using System.Collections;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.IO.Enumeration;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using fh_res;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


//Declare full path to signature JSON file
//JSON retrieved from https://github.com/qti3e renamed file to signatures.json
string signatureFilePath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\signatures.json";
//update
//Declare list type signature into which the magic contents will be loaded
List<Signature> signature = new();

//Load magic text contents into signature object
FileOperations.LoadJson(signatureFilePath, ref signature); //ref used as it can be modified


//DisplayHeaders(ref signature);//Display all headers
//DisplayHeaders_SearchByExtension("docx", in signature);
//DisplayHeaders_SearchByHex("44", in signature);
//GetFileType("C:\\Users\\Admin\\Documents\\Win10_1703_English_x64.iso", "-1",
//    in signature); //in is cannot be changed

//GetFileType("C:\\Users\\Admin\\Documents\\Win10_1703_English_x64.iso", "C:\\Users\\Admin\\Desktop1\\out.txt",
//    in signature); //in is cannot be changed
//DisplayHeaders_SearchByExtension("lha", ref signature); //id 16 has na offset of 2
//PatchBytes("C:\\Users\\Admin\\Desktop\\text.xlsx", "16", ref signature);4d5a
//byte[] temp = Convert.FromHexString("0x4d 0x5a".Replace("0x","").Replace(" ",""));
//PatchBytesCustomRange("C:\\Users\\Admin\\Desktop\\test123.xlsx", "7468", "0x4f0");
//ReadCustomByteRange("C:\\Users\\Admin\\Desktop\\text.xlsx", "2", "3");
//ReadBytes("C:\\Users\\Admin\\Desktop\\text.xlsx", "384", "19");
//ReadCustomByteRange_Offset("C:\\Users\\Admin\\Desktop\\text.xlsx", "0x180", "0x193", "C:\\Users\\Admin\\Desktop\\rcro1.txt");
//DisplayFileHash("C:\\Users\\Admin\\Desktop\\test123.xlsx", "all");
switch (args[0])
{
    case "-h":
        Console.WriteLine("\n------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("-------------------------                                 FILE HEADER RESOLVER v1.0  (BETA)                                ---------------------");
        Console.WriteLine("-------------------------                                                    with added patching/carving/hashing features  ---------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
        Console.WriteLine("\n{0,-25} {1,-60} {2,-50}", "Command/s", "Usage", "Notes");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh (display header)", "-dh", "Return all stored headers.  Use | more for paging");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh --search-ext", "-dh --search-ext \"keyword\"", "Case-insensitive search");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Contained within search e.g. \"if\" returns GIF");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh --search-hex", "-dh --search-hex \"hex value\\s\"", "Must NOT be space seperated e.g. \"4D5A\"");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Case-insensitive search");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Contained within search e.g. \"4D\" returns 42 4D");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"FilePath\"", "Get the file type");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"FilePath\" \"NewFilePath\"", "Get the file type and write results to file");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pb (patch byte/s)", "-pb \"FilePath\" \"FileIndex\"", "Patch the header at offset specified in JSON file");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Use the -dh command to get the file index");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "NOTE:  Use at your own risk.  Always backup files first.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pc (patch custom)", "-pc \"FilePath\" \"hex value\\s\" \"offset\"", "Apply custom patch starting at specified offset");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "NOTE:  Use at your own risk.  Always backup files first.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-cb (carve byte/s)", "-cb \"FilePath\" \"Start Offset\" \"End Offset\" \"NewFilePath\"", "Carve out bytes from file and save ouput to a new file.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-fh (file hash)", "-fh \"FilePath\" \"Hash Type\"", "Generate file hashes.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "\"Hash Type\" options: MD5, SHA1, SHA256, SHA384, SHA512");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "\"Hash Type\" additional option: \"ALL\" will generate all");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "file hashes as specified above");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        break;
    case "-ft":
        if (args.Length == 2) //this is write to screen
        {
            if (File.Exists(args[1]))
            {
                FileOperations.GetFileType(args[1], "-1", in signature); //arg[1]:  File path to get type of, arg[2]:  -1 denoting an output to screen
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else if (args.Length == 3) //this is a write to file
        {
            if (File.Exists(args[1]))
            {
                if (Directory.Exists(Path.GetDirectoryName(args[2])))
                {
                    FileOperations.GetFileType(args[1], args[2], in signature); //arg[1]:  File path to get type of, arg[2]:  list of headers //in used as must not be modified
                }
                else { Console.WriteLine("Error:  An invalid path was given in which to output the results!!!"); }           
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage (Option A):  -pb \"FilePath\" ");
            Console.WriteLine("Usage (Option B):  -pb \"FilePath\" \"NewFilePath\"");
        }
        break;
    case "-pb":
        if (args.Length == 3)
        {
            //Patch the file with the selected header from the header list
            FileOperations.PatchBytes(args[1], args[2], ref signature);//arg[1]:  File path of file to patch, arg[2]:  Index of header to patch with, arg[3]:  list of headers
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -pb \"FilePath\" \"FileIndex\"");
        }
        break;
    case "-pc": //DONE
        if (args.Length==4)
        {
            //Patch the file with the selected header from the header list
            FileOperations.PatchBytesCustomRange(args[1], args[2], args[3]);//arg[1]:  File path of file to patch, arg[2]:  Index of header to patch with, arg[3]:  list of headers
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -pc \"FilePath\" \"hex value\\s\" \"offset\"");
        }     
        break;
    case "-cb": //DONE
        if (args.Length == 5)
        {
            //Read bytes at offset and return hex and ASCII values
            FileOperations.ByteCarver_Offset(args[1], args[2], args[3], args[4]); //arg[1]: FilePath arg[2]: Offset  arg[3]: Length to read
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -cb \"FilePath\" \"Start Offset\" \"End Offset\" \"NewFilePath\"");
        }
        break;
    case "-dh":
        //Display headers list
        if (args.Length == 1)
        {
            FileOperations.DisplayHeaders(ref signature);//Display all headers
        }
        else if (args.Length == 3)
        {
            if (args[1] == "--search-ext") { FileOperations.DisplayHeaders_SearchByExtension(args[2], in signature); } //Serach by type }
            else if (args[1] == "--search-hex") { FileOperations.DisplayHeaders_SearchByHex(args[2], in signature); } //Serach by hex }
        }
        break;
    case "-fh":
        if (args.Length==3)
        {
            if (File.Exists(args[1]))
            {
                FileOperations.DisplayFileHash(args[1],args[2]);
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -fh \"FilePath\" \"Hash Type\"");
        }
        break;
    default:
        Console.WriteLine("Error:  Unknown command!!!");
        Console.WriteLine("Press enter to exit....");
        Console.ReadLine();
        break;
}