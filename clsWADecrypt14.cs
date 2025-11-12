using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WAWorks
{
    public class clsWADecrypt14
    {
        public clsWADecrypt14() { }

        byte[] data, iv, tag, checksum, ciphertext;
        int fileLen;
        int cipherStart = 194;
        int tagLen = 16;
        int checksumLen = 16;
        public void doJob()
        {
            data = File.ReadAllBytes("d:/b2/msgstore-increment-4-2025-08-15.1.db.crypt14");
            fileLen = data.Length;

            // 4) IV’yi sen zaten ölçtün: offset 67, 16 byte
            iv = new byte[16];
            Array.Copy(data, 67, iv, 0, 16);

            // 5) dosyanın son 32 baytı: 16 tag + 16 checksum

            tag = data.Skip(fileLen - 32).Take(tagLen).ToArray();
            checksum = data.Skip(fileLen - 16).Take(checksumLen).ToArray();

            // 6) ciphertext = header sonu .. (EOF-32)
            int cipherEnd = fileLen - 32;
            int cipherLen = cipherEnd - cipherStart;
            if (cipherLen <= 0)
                throw new Exception("ciphertext length is invalid");

            ciphertext = new byte[cipherLen];
            Array.Copy(data, cipherStart, ciphertext, 0, cipherLen);


            Decrypt("d:/b2/key."); //, "d:/b2/out.db");
        }

        public bool Decrypt(string keyPath)//, string outPath)
        {
            byte[] keyFile = File.ReadAllBytes(keyPath);
            byte[] aesKey = keyFile.Skip(keyFile.Length - 32).Take(32).ToArray();

            int pos = 0;
            int protoLen = data[pos];
            pos += 1;

            bool hasFeature = data[pos] == 0x01;
            if (hasFeature)
                pos += 1;

            int headerStart = pos;
            int headerEnd = headerStart + protoLen;

            var gcm = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(aesKey), 128, iv, null);
            gcm.Init(false, parameters);

            byte[] cipherPlusTag = new byte[ciphertext.Length + tagLen];
            Buffer.BlockCopy(ciphertext, 0, cipherPlusTag, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, cipherPlusTag, ciphertext.Length, tagLen);

            byte[] plain = new byte[gcm.GetOutputSize(cipherPlusTag.Length)];
            int outLen = gcm.ProcessBytes(cipherPlusTag, 0, cipherPlusTag.Length, plain, 0);
            outLen += gcm.DoFinal(plain, outLen);

            byte[] decompressed;
            using (var input = new MemoryStream(plain))
            {
                // zlib header'ı kontrol et
                int b1 = input.ReadByte();
                int b2 = input.ReadByte();

                // zlib ise 0x78 ile başlar
                bool isZlib = (b1 == 0x78);
                Stream deflateStream;

                if (isZlib)
                {
                    // header'ı yedik zaten, kalanını ver
                    deflateStream = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress);
                }
                else
                {
                    // zlib değilse başa sar ve direkt dene
                    input.Position = 0;
                    deflateStream = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress);
                }

                using (deflateStream)
                using (var outMs = new MemoryStream())
                {
                    deflateStream.CopyTo(outMs);
                    decompressed = outMs.ToArray();
                }
            }

            //File.WriteAllBytes(outPath, decompressed);
            //Console.WriteLine("Decompressed size: " + decompressed.Length);

            if (decompressed[0] == 'P' && decompressed[1] == 'K')
            {
                return true;
            }
            else
            {
                return false;
            }


        }
    }
}
