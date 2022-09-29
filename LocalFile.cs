using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using System.Globalization;
using System.Threading.Tasks.Sources;
using System.Diagnostics;

namespace fh_res
{
    /// <summary>
    /// Represents a file object from which specific object instance attribute information can be attained/processed.
    /// </summary>
    class LocalFile 
    {
        public string FullPath { get; set; }
        public string Name { get; }
        public long FileSize { get; }
        public DateTime CreatedDate { get; }
        public DateTime LastModifiedDate { get; }
        public DateTime LastAccessed { get; }

        public LocalFile(string fullPath)
        {
            FullPath = fullPath;
            Name = GetFileName();
            FileSize = GetFileSize();
            CreatedDate = GetCreatedDate();
            LastModifiedDate = GetLastModifiedDate();
            LastAccessed = GetLastAccessed();
        }

        private long GetFileSize()
        {
            long fileSize = new System.IO.FileInfo(FullPath).Length; 
            return fileSize;
        }

        private DateTime GetCreatedDate()
        {
            DateTime fileCreatedDate = new System.IO.FileInfo(FullPath).CreationTime; 
            return fileCreatedDate;
        }
        private DateTime GetLastModifiedDate()
        {
            DateTime fileLastModifiedDate = new System.IO.FileInfo(FullPath).LastWriteTime; 
            return fileLastModifiedDate;
        }
        private DateTime GetLastAccessed()
        {
            DateTime fileLastAccessed = new System.IO.FileInfo(FullPath).LastAccessTime; 
            return fileLastAccessed;
        }

        private string GetFileName()
        {
            return Path.GetFileName(FullPath);
        }

        public string GetMD5Hash()//Thanks and credit to João Sousa post on the MSDN forum for this method on hashing
        {
            using var md5 = MD5.Create();
            using var stream = File.OpenRead(FullPath);
            return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty);
        }


        public string GetSHA1Hash()
        {
            using var sha1 = SHA1.Create();
            using var stream = File.OpenRead(FullPath);
            return BitConverter.ToString(sha1.ComputeHash(stream)).Replace("-", string.Empty);
        }

        public string GetSHA256Hash()
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(FullPath);
            return BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", string.Empty);
        }

        public string GetSHA384Hash()
        {
            using var sha384 = SHA384.Create();
            using var stream = File.OpenRead(FullPath);
            return BitConverter.ToString(sha384.ComputeHash(stream)).Replace("-", string.Empty);
        }

        public string GetSHA512Hash()
        {
            using var sha512 = SHA512.Create();
            using var stream = File.OpenRead(FullPath);
            return BitConverter.ToString(sha512.ComputeHash(stream)).Replace("-", string.Empty);
        }

    }
}
