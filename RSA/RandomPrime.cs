using System;

namespace RSA
{
    public class RandomPrime
    {
        // 使用100内的素数实现RSA，或者用其他算法即时生成
        private static readonly int[] PrimeTable =
            {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};

        private static readonly Random Rand = new Random();

        /// <summary>
        /// 随机获得表里的素数
        /// </summary>
        /// <returns></returns>
        private static int GetPrime()
        {
            return PrimeTable[Rand.Next(PrimeTable.Length)];
        }

        /// <summary>
        /// 生产两个互素的素数
        /// </summary>
        /// <returns></returns>
        public static Tuple<int, int> FindPrime()
        {
            var prime1 = GetPrime();
            var prime2 = GetPrime();
            while (prime2 == prime1)
            {
                prime2 = GetPrime();
            }
            return new Tuple<int, int>(prime1, prime2);
        }
    }
}