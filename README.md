WhatsApp DeCrypt C#

WhatsApp crypt14 files are encrypted with AES GCM 256.

Accordind C# code, crypted WhatsApp db file can be decrypted.
After decryption , result raw file is compressed ZLib file and needs to be deflated.


For the key file last 32 byte is the key, we just need this

For the Crypted db file:

IV starting from offset 67 and 16 bytes length
CipherText starts from offset 194

(if you need help about the offsets , wainfo or wadecypt with -v parameter could help)
Umut Can ÖZCAN (11.25)
