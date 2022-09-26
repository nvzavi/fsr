
using System;
using System.Collections;
using System.Collections.Concurrent;
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


/*really cool extensions.json file is used as my reference database and it was retreived
from https://github.com/qti3e (Specific gist https://gist.github.com/Qti3e/6341245314bf3513abb080677cd1c93b)*/

string signatureFilePath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\extensions.json";
List<Signature> signature = new();
FileOperations.LoadJson(signatureListFilePath: signatureFilePath, signatureList: in signature);

switch (args[0])
{
    case "-h":
        Console.WriteLine("\n--------------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("-------------------------                              FILE SIGNATURE RESOLVER v1.0  (BETA)                                -----------------------------");
        Console.WriteLine("-------------------------                                                    with added patching/carving/hashing features  -----------------------------");
        Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "Command/s", "Usage", "Description");
        Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "-dh (display header)", "-dh", "Return the complete list of file signatures together with");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "additional signature attributes that is contained within");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "the accompanying JSON file.  Use '| more' for paging");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-dh --search-ext", "-dh --search-ext searchExtKeyWord", "Return a list of file signatures that matched with the");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "specified file extension 'searchExtKeyWord' and the");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "extension that is contained within the accompanying JSON");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "file.");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-dh --search-hex", "-dh --search-hex searchHexKeyWord", "Return a list of file signatures that matched with the");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "specified byte sequence in hex (base 16) 'searchHexKeyWord'");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "and the byte sequence that is contained within the");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "accompanying JSON file.");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-ft (file type)", "-ft fileFullPath", "Return a list possible file signatures that may be");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "associated with the specified file 'fileFullPath'.");      
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-ft (file type)", "-ft fileFullPath fileOutputFullPath", "Return a list possible file signatures that may be");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "associated with the specified file 'fileFullPath', and the");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "output is written to file 'fileOutputFullPath'.");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-pb (patch byte/s)", "-pb fileFullPath searchId", "Patch a specified file's signature 'fileFullPath' byte");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "sequence with an available signature ID 'searchId' that");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "is associated with a particular file type contained");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "within the accompanying signature JSON file.");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "TIP:  Use the '-dh' command options to get the 'searchId'.");     
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-pc (patch custom)", "-pc fileFullPath hexSequence startingHexOffSet", "Patch a specified file's signature 'fileFullPath' byte");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "sequence at offset 'startingHexOffSet' with a custom byte");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "sequence 'hexSequence'.");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-cb (carve byte/s)", "-cb fileFullPath startingHexOffSet endingHexOffSet fileOutputFullPath", "Carve out a byte sequence from the specified");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "file 'fileFullPath' at starting offset 'startingHexOffSet'");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "and ending offset 'endingHexOffSet'.  The ouput is written");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "to file 'fileOutputFullPath'.");
        Console.WriteLine("\n{0,-22} {1,-70} {2,-50}", "-fh (file hash)", "-fh fileFullPath hashType", "Generate the required hash value for the specified");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "file 'fileFullPath' using the hash algorithm 'hashType'.");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "Hashing options for 'hashType' include: md5, sha1,");
        Console.WriteLine("{0,-22} {1,-70} {2,-50}", "", "", "sha256, sha384 and sha512.");
        Console.WriteLine("--------------------------------------------------------------------------------------------------------------------------------------------------------");
        break;
    case "-ft"://file type
        if (args.Length==2) { FileOperations.GetFileType(fileFullPath: args[1], signatureList: in signature); }
        else if (args.Length== 3) { FileOperations.GetFileType(fileFullPath: args[1], signatureList: in signature, fileOutputFullPath: args[2]); }
        else { goto default; }
        break;
    case "-pb"://patch  byte/s
        if (args.Length == 3)
        {
            FileOperations.PatchBytes(fileFullPath: args[1], searchId: Convert.ToInt32(args[2]), signatureList: in signature);
        }
        else { goto default; }
        break;
    case "-pc"://patch custom byte/s
        if (args.Length==4)
        {
            FileOperations.PatchBytesCustomRange(fileFullPath: args[1], hexSequence: args[2], startingHexOffSet: args[3]);
        }
        else { goto default; }     
        break;
    case "-cb"://carve byte/s  
        if (args.Length == 5)
        {
            FileOperations.ByteCarverByOffsets(fileFullPath: args[1], startingHexOffSet: args[2], endingHexOffSet: args[3], fileOutputFullPath: args[4]); 
        }
        else { goto default; }
        break;
    case "-dh"://display header
        if (args.Length == 1) { FileOperations.DisplayHeaders(signatureList: in signature); }
        else if (args.Length == 3)
        {
            if (args[1] == "--search-ext") { FileOperations.DisplayHeadersSearchByExtension(searchExtKeyWord: args[2], signatureList: in signature); } 
            else if (args[1] == "--search-hex") { FileOperations.DisplayHeadersSearchByHex(searchHexKeyWord: args[2], signatureList: in signature); } 
            else { goto default; }
        }
        else { goto default; }
        break;
    case "-fh"://file hash
        if (args.Length==3)
        {
            FileOperations.DisplayFileHash(fileFullPath: args[1], hashType: args[2]);
        }
        else { goto default; }
        break;
    default:
        Console.WriteLine("Error: Please enter the required commands/arguments!!! \nUse command fh_res -h to view the help window");
        break;
}