# File Header Resolver (fsr) BETA
A windows console tool that automates some of the manual tasks of reviewing a specified file's signature and overall layout (at a byte level) inorder to ascertain the true nature of the specified file's intentions (example: check if it may be injected and as such, verify if its a possible dropper).
* The following tasks are automated *(based on your selected usage argument)*:  
  * Lookup the file signature of various file types 
  * Quickly Identify the file signature that might by associated with a specified file 
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using an avaiable signature that is contained with the accompanying signature JSON file
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using a custom byte sequence 
  * Generate MD5 / SHA1 / SHA256 / SHA384 / SHA512 hashes of a specified byte.
