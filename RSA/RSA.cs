using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RSA
{
    public class Rsa
    {
        public RsaInfo Info { get; set; }
        private readonly SHA1CryptoServiceProvider _sha1 = new SHA1CryptoServiceProvider();

        /// <summary>
        /// 生产密钥，按照书本方法
        /// </summary>
        /// <returns></returns>
        public RsaInfo GenerateKeys()
        {
            var pq = RandomPrime.FindPrime();
            var info = new RsaInfo
            {
                p = pq.Item1,
                q = pq.Item2
            };
            info.n = info.p * info.q;
            info.fn = (info.p - 1) * (info.q - 1);
            var rand = new Random();
            info.e = rand.Next(2, info.fn);
            while (Gcd(info.e, info.fn) != 1)
            {
                info.e = rand.Next(2, info.fn);
            }
            // 使用扩展欧几里得算法求得d和k。用k 0-1000 的循环试求d效率较低，而且不适用p和q较大时
            var dk = ExGcd(info.e, info.fn);
            info.d = dk.Item1;
            info.k = dk.Item2;
            while (info.d <= 0)
            {
                info.d += info.fn;
            }
            return info;
        }


        public int[] EncryptBytes(byte[] bytes)
        {
            //先使用 Base64 编码，使 Unicode 字符用 ASCII 码表示，再对每个字节加密,实现中文加密，类似分组密码的思想，分组长度为字节长。
            var b64Msg = Convert.ToBase64String(bytes);
            InitKeys();
            //使用公钥加密
            return b64Msg.Select(chr => Compute(chr, Info.PublicKey.Item1, Info.PublicKey.Item2)).ToArray();
        }


        public byte[] DecryptBytes(int[] msg)
        {
            InitKeys();

            var a = Encoding.ASCII.GetString(msg
                //使用私钥解密
                .Select(chr =>
                {
                    var b = Compute(chr, Info.PrivateKey.Item1, Info.PrivateKey.Item2);
                    return (byte) b;
                }).ToArray());

            return Convert.FromBase64String(a);
        }

        public int[] SignHash(byte[] hash)
        {
            return hash.Select(b => Compute(b, Info.PrivateKey.Item1, Info.PrivateKey.Item2)).ToArray();
        }

        public byte[] VerifyHash(int[] hash)
        {
            return hash.Select(b => (byte)Compute(b, Info.PublicKey.Item1, Info.PublicKey.Item2)).ToArray();
        }

        public byte[] HashBytes(byte[] msg)
        {
            return _sha1.ComputeHash(msg);
        }

        /// <summary>
        /// 加解密算法
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="arg1">e或d</param>
        /// <param name="arg2">n</param>
        /// <returns></returns>
        private int Compute(int msg, int arg1, int arg2)
        {
            return PowMod(msg, arg1, arg2);
        }

        // 平方乘的书本实现，可以使用。但实际用应该有bug，有溢出的嫌疑，因为解密时有小几率崩溃，
        private static int PowMod(int msg, int pow, int n)
        {
            // 将幂转换成二进制数组
            var bits = Convert.ToString(pow, 2).ToCharArray();
            var d = 1;
            foreach (var bit in bits)
            {
                d = d * d % n;
                if (bit == '1')
                {
                    d = d * msg % n;
                }
            }
            return d;
        }

        // 快速乘，导致会导致中间量过大，不能用
        private static int IntPow(int x, int pow)
        {
            var ret = 1;
            while (pow != 0)
            {
                if ((pow & 1) == 1)
                    ret *= x;
                x *= x;
                pow >>= 1;
            }
            return ret;
        }

        private void InitKeys()
        {
            if (Info == null)
            {
                UseKeys(GenerateKeys());
            }
        }


        public void UseKeys(RsaInfo info)
        {
            Info = info;
        }

        /// <summary>
        /// 扩展欧几里得算法
        /// </summary>
        /// <param name="n"></param>
        /// <param name="m"></param>
        /// <returns></returns>
        private static Tuple<int, int> ExGcd(int n, int m)
        {
            if (m == 0)
            {
                return new Tuple<int, int>(1, 0);
            }
            else
            {
                var res = ExGcd(m, n % m);
                var x = res.Item1;
                var y = res.Item2;
                var t = x;
                x = y;
                y = t - n / m * y;
                return new Tuple<int, int>(x, y);
            }
        }

        /// <summary>
        /// 辗转相除法
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        private static int Gcd(int a, int b)
        {
            if (0 != b) while (0 != (a %= b) && 0 != (b %= a)) ;
            return a + b;
        }
    }

    public class RsaInfo
    {
        private Tuple<int, int> _publicKey;
        public Tuple<int, int> PublicKey => _publicKey ?? (_publicKey = new Tuple<int, int>(e, n));
        private Tuple<int, int> _privateKey;
        public Tuple<int, int> PrivateKey => _privateKey ?? (_privateKey = new Tuple<int, int>(d, n));
        public int p { get; set; }
        public int q { get; set; }
        public int n { get; set; }
        public int fn { get; set; }
        public int e { get; set; }
        public int d { get; set; }
        public int k { get; set; }
    }
}