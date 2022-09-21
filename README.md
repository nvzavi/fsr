# File Signature Resolver (fsr) BETA
A windows console tool that automates some of the manual tasks of reviewing a specified file's signature and overall layout (at a byte level) inorder to ascertain the true nature of the specified file's intentions (example: check if it may be injected and as such, verify if its a possible dropper).
* The following tasks are automated *(based on your selected usage argument)*:  
  * Lookup the file signature of various file types that is contained within the accompanying signature JSON file
  * Quickly Identify the file signature that might by associated with a specified file 
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using an available signature that is contained within the accompanying signature JSON file
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using a custom byte sequence 
  * Quickly carve a byte sequence within a specifed offset range.
  * Generate MD5 / SHA1 / SHA256 / SHA384 / SHA512 hashes of a specified byte.

<h2>Arguments include:</h2>

Argument | Description
------------ | -------------
-h  | Display the help window.
-dh  | Return the complete list of file signatures together with additional signature attributes that is contained within the accompanying signature JSON file.
-dh --search-ext `searchExtKeyWord` | Return a list of file signatures that matched with the specified file extension `searchExtKeyWord` and the extension that is contained within the accompanying signature JSON file.  
-dh --search-hex `searchHexKeyWord` | Return a list of file signatures that matched with the specified byte sequence in hex (base 16) `searchHexKeyWord` and the byte sequence that is contained within the accompanying signature JSON file.  
-ft `fileFullPath` | Return a list possible file signatures that may be associated with the specified file `fileFullPath`. <br/><br/> The output is listed/sorted by degree of probability "high" to "low".
-ft `fileFullPath` `fileOutputFullPath` | Return a list possible file signatures that may be associated with the specified file `fileFullPath`, and the ouput is wrriten to file `fileOutputFullPath`.<br/><br/> If the argument `fileOutputFullPath` already exists then a new file with the same file name together with an appended string '\_fhgen\_{random number}' will be created.<br/><br/> The output is listed/sorted by degree of probability "high" to "low".
-pb `fileFullPath` `searchId` | Patch a specified file's signature `fileFullPath` byte sequence with an available signature ID `searchId` that is associated with a particular file type contained within the accompanying signature JSON file.
-pc `fileFullPath` `hexSequence` `startingHexOffSet` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| Patch a specified file's signature `fileFullPath` byte sequence at offset `startingHexOffSet` with a custom byte sequence. `hexSequence`.
-cb `fileFullPath` `startingHexOffSet` `endingHexOffSet` `fileOutputFullPath` | Carve out a byte sequence from the specified file `fileFullPath` at starting offset `startingHexOffSet` and ending offset `endingHexOffSet`.  <br/> <br/> The ouput is written to file `fileOutputFullPath`.
-fh `fileFullPath` `hashType` | Generate the required hash value for the specified file `fileFullPath` using the hash algorithm `hashType`.  <br/> <br/> Hashing options for `hashType` include:  md5, sha1, sha256, sha384 and sha512.

Examples: 
--------
Command:  fsr -dh
<br/>Output:  
> ```
> ID:                  13
> Extension:           doc
> Offset:              512 (base 10) / 0x200 (base 16)
> Value at offset:     ECA5C100 (base 16)
> ASCII:               ì¥A
> MIME:                application/msword
> ---------------------------------------------
> ID:                  14
> Extension:           mxf
> Offset:              0 (base 10) / 0x0 (base 16)
> Value at offset:     060E2B34020501010D0102010102 (base 16)
> ASCII:               +4
> MIME:                application/mxf
> ```
Command:  fsr -dh --search-ext doc
<br/>Output:
> ```
> ID:                  13
> Extension:           doc
> Offset:              512 (base 10) / 0x200 (base 16)
> Value at offset:     ECA5C100 (base 16)
> ASCII:               ì¥A
> MIME:                application/msword
> ---------------------------------------------
> ID:                  87
> Extension:           docx
> Offset:              0 (base 10) / 0x0 (base 16)
> Value at offset:     504B030414000600 (base 16)
> ASCII:               PK
> MIME:                application/vnd.openxmlformats-officedocument.wordprocessingml.document
> ```
Command:  fsr -dh --search-hex 504B
<br/>Output:
> ```
> ID:                  87
> Extension:           docx
> Offset:              0 (base 10) / 0x0 (base 16)
> Value at offset:     504B030414000600 (base 16)
> ASCII:               PK
> MIME:                application/vnd.openxmlformats-officedocument.wordprocessingml.document
> ---------------------------------------------
> ID:                  207
> Extension:           jar
> Offset:              0 (base 10) / 0x0 (base 16)
> Value at offset:     504B0304140008000800 (base 16)
> ASCII:               PK
> MIME:                application/x-java-archive
> ```
Command:  fsr -ft C:\folder\fileName.docx
<br/>Output:
> ```
> Probability:                   high
> Extension:                     docx
> Offset (expected):             0 (base 10) - 0x0(base 16)
> Hexadecimal (expected):        504B030414000600
> ASCII (expected):              PK
> Mime:                          application/vnd.openxmlformats-officedocument.wordprocessingml.document
> 
> Additional file signature entries for 'docx' with hexadecimal value '504B030414000600' were found within the current file
> Located Offset/s:              0x0 <--match / 0x393 / 0x6B3 / 0x8E9 / 0xB81 / 0x11D8 ***
> ----------------------------------------------------------------------------------------------
> Probability:                   low
> Extension:                     ntf
> Offset (expected):             0 (base 10) - 0x0(base 16)
> Hexadecimal (expected):        1A0000
> ASCII (expected):
> Mime:                          application/vnd.lotus-notes
> 
> Additional file signature entries for 'ntf' with hexadecimal value '1A0000' were found within the current file
> Located Offset/s:              0xB98 / 0x2AA7
Command:  fsr -ft C:\folder\fileName.docx C:\folder\output.txt
<br/>Output:
> ```
> Output written to file: C:\folder\output.txt
> ```
