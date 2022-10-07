using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Schema;

namespace fsr
{
    public class JsonService
    {
        public string SignatureListFilePath { get; set; }

        /// <summary>
        /// JsonService constructor
        /// </summary>
        /// <param name="signatureListFilePath">Full file path to the extensions.json file</param>
        public JsonService(string signatureListFilePath)
        {
            SignatureListFilePath = signatureListFilePath;
        }

        /// <summary>
        /// Validate the JSON schema 
        /// </summary>
        /// <returns>A boolean value (true or false) indicating if the JSON file is valid</returns>
        public bool ValidJSON()
        {   //TODO:  Set extension key to be required in schema
            string schemaJson = @"{ 
                        'type': 'object',
                        'additionalProperties': {
                        'type': 'object',
                        'properties': {
                            'signs': {
                                'type': 'array',
                                'items': [ { 'type': 'string' } ] 
                                 },
                            'mime': { 'type': 'string' } },
                            'required': [ 'signs', 'mime' ]
                        }}";

            JSchema schema = JSchema.Parse(schemaJson);
            using StreamReader sReader = new(SignatureListFilePath);
            string readString = sReader.ReadToEnd();
            JObject signObject = JObject.Parse(readString);
            bool result = signObject.IsValid(schema);
            return result;
        }

        /// <summary>
        /// Load the extensions.json file into a type List 
        /// </summary>
        /// <returns>Returns a populated list object</returns>
        public List<Signature> LoadJson()
        {
            List<Signature> signatureList = new();
            List<StagingSignature> stagingSignature = new();

            try
            {
                using StreamReader sReader = new(SignatureListFilePath);
                string readString = sReader.ReadToEnd();
                var signObject = JObject.Parse(readString);
                foreach (var keyValuePair in signObject)
                {
                    if (keyValuePair.Value != null)
                    {
                        var deserializable = keyValuePair.Value.ToString();

                        if (keyValuePair.Key != null)
                        {
                            var sign = JsonConvert.DeserializeObject<StagingSignature>(deserializable);
                            if (sign != null)
                            {
                                if (sign.Signs != null)
                                {
                                    sign.Name = keyValuePair.Key;
                                    stagingSignature.Add(new StagingSignature(sign.Name, sign.Signs, sign.Mime));
                                }
                            }
                        }
                    }
                }
                int stagingCounter = 1;
                foreach (StagingSignature signs in stagingSignature)
                {
                    foreach (var stringValue in signs.Signs)
                    {
                        int offset = Convert.ToInt32(stringValue[..stringValue.IndexOf(',')]);
                        string hexValue = stringValue[(stringValue.IndexOf(',') + 1)..];
                        signatureList.Add(new Signature(stagingCounter, signs.Name, offset, hexValue, signs.Mime));
                        stagingCounter++;
                    }
                }
                sReader.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error:" + ex.Message);
            }
            return signatureList;
        }
    }
}
