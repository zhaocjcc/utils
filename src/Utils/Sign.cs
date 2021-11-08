using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Utils
{
    public class RSA
    {
        /// <summary>
        /// 公钥签名
        /// </summary>
        /// <param name="publickey"></param>
        /// <param name="content"></param>
        /// <returns></returns>
        public static string PubRSAEncrypt(string publickey, string content)
        {
            using (RSACryptoServiceProvider RSACryptography = new RSACryptoServiceProvider())
            {
                Byte[] PlaintextData = Encoding.UTF8.GetBytes(content);
                RSACryptography.FromXmlString(publickey);
                int MaxBlockSize = RSACryptography.KeySize / 8 - 11;    //加密块最大长度限制
                if (PlaintextData.Length <= MaxBlockSize)
                    return Convert.ToBase64String(RSACryptography.Encrypt(PlaintextData, false));
                using (MemoryStream PlaiStream = new MemoryStream(PlaintextData))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    while (BlockSize > 0)
                    {
                        Byte[] ToEncrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);
                        Byte[] Cryptograph = RSACryptography.Encrypt(ToEncrypt, false);
                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);
                        BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    }
                    return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
                }
            }
        }

        /// <summary>
        /// 将公钥加密的数据解密
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string Decrypt(string privatekey, string content)
        {
            RSACryptoServiceProvider rSACryptoServiceProvider = new RSACryptoServiceProvider();
            rSACryptoServiceProvider.FromXmlString(privatekey);
            // 解密后得到一个byte[] 数组
            byte[] DecryptBuffer = rSACryptoServiceProvider.Decrypt(Convert.FromBase64String(content), false);
            // 将byte[]转换为明文
            return Encoding.UTF8.GetString(DecryptBuffer); 
        }

        //RSA私钥签名
        public static string PriRSAEncrypt(string privatekey, string content)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] cipherbytes;
            rsa.FromXmlString(privatekey);
            cipherbytes = rsa.SignData(Encoding.UTF8.GetBytes(content), "SHA1");
            return Convert.ToBase64String(cipherbytes);
        }

        //RSA公钥验证
        public static bool RSAVerifyData(string publickey, string content, string sign)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publickey);
            return rsa.VerifyData(Encoding.UTF8.GetBytes(content), "SHA1", Convert.FromBase64String(sign));
            //rsa.VerifyData()
        }
    }
}
