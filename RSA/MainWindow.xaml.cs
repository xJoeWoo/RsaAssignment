using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace RSA
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        private Rsa _rsa = new Rsa();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void TbInputEncrypt_OnTextChanged(object sender, TextChangedEventArgs e)
        {
            UpdateMsg();
        }

        private void TbInputDecrypt_OnTextChanged(object sender, TextChangedEventArgs e)
        {
            var text = TbInputDecrypt.Text;
            if (string.IsNullOrEmpty(text))
            {
                TbDecrypt.Text = string.Empty;
                return;
            }
            TbDecrypt.Text =
                Encoding.UTF8.GetString(_rsa.DecryptBytes(text.Split(',').Select(str => int.Parse(str)).ToArray()));
        }

        private void BtnNewKey_OnClick(object sender, RoutedEventArgs e)
        {
            _rsa.UseKeys(_rsa.GenerateKeys());
            UpdateMsg();
        }

        private void UpdateMsg()
        {
            var text = TbInputEncrypt.Text;
            var encryptedMsg = _rsa.EncryptBytes(Encoding.UTF8.GetBytes(text));
            var first = true;
            var builder = new StringBuilder();
            var res = ConstructEncryptedMsg(encryptedMsg);
            TbInputDecrypt.Text = res;
            TbEncrypt.Text = res;

            var hash = _rsa.HashBytes(Encoding.UTF8.GetBytes(text));

            TbDataHash.Text = Convert.ToBase64String(hash);
            TbSignHash.Text = ConstructEncryptedMsg(_rsa.SignHash(hash));
            TbDataSignHash.Text = $"{text}|{TbSignHash.Text}";

            UpdateRsaInfo();
        }

        private void UpdateRsaInfo()
        {
            TxtInfo.Text =
                $"p: {_rsa.Info.p}, q: {_rsa.Info.q}, n: {_rsa.Info.n}, Φn: {_rsa.Info.fn}, e: {_rsa.Info.e}, k: {_rsa.Info.k}, d: {_rsa.Info.d}";
        }

        private string BytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
        }

        private void TbDataSignHash_OnTextChanged(object sender, TextChangedEventArgs e)
        {
            var msgAndSignature = TbDataSignHash.Text.Split('|');

            TbVerifyHash.Text =
                $"{Convert.ToBase64String(_rsa.HashBytes(Encoding.UTF8.GetBytes(msgAndSignature[0])))}\n----------------\n{Convert.ToBase64String(_rsa.VerifyHash(msgAndSignature[1].Split(',').Select(str => int.Parse(str)).ToArray()))}";
        }

        private string ConstructEncryptedMsg(int[] msg)
        {
            var builder = new StringBuilder();
            var first = true;
            foreach (var h in msg)
            {
                builder.Append(!first ? "," : string.Empty).Append(h.ToString());
                first = false;
            }
            return builder.ToString();
        }

        private const string MsgFileName = "msg.txt";
        private const string CipherTextFileName = "cipher_text.txt";
        private const string KeyFileName = "key.txt";

        private void BtnLoadMsg_OnClick(object sender, RoutedEventArgs e)
        {
            TbInputEncrypt.Text = ReadFile(MsgFileName);
        }

        private void BtnSaveMsg_OnClick(object sender, RoutedEventArgs e)
        {
            WriteFile(MsgFileName, TbInputEncrypt.Text);
        }

        private void BtnLoadKey_OnClick(object sender, RoutedEventArgs e)
        {
           LoadKey();
        }

        private void BtnSaveKey_OnClick(object sender, RoutedEventArgs e)
        {
            SaveKey();
           }

        private bool LoadKey()
        {
            var flag = false;
            var args = ReadFile(KeyFileName).Split(',');
            var rsaInfo = new RsaInfo();
            foreach (var arg in args)
            {
                flag = true;
                var info = arg.Split('=');
                var value = int.Parse(info[1]);
                switch (info[0])
                {
                    case "p":
                        rsaInfo.p = value;
                        break;
                    case "q":
                        rsaInfo.q = value;
                        break;
                    case "n":
                        rsaInfo.n = value;
                        break;
                    case "fn":
                        rsaInfo.fn = value;
                        break;
                    case "e":
                        rsaInfo.e = value;
                        break;
                    case "d":
                        rsaInfo.d = value;
                        break;
                    case "k":
                        rsaInfo.k = value;
                        break;
                }
            }
            if (flag)
            {
                _rsa.Info = rsaInfo;
                UpdateMsg();
            }
            return flag;
        }

        private void SaveKey()
        {
            var info = _rsa.Info;
            WriteFile(KeyFileName, $"p={info.p},q={info.q},n={info.n},fn={info.fn},e={info.e},d={info.d},k={info.k}");
        }

        private void BtnLoadCipherText_OnClick(object sender, RoutedEventArgs e)
        {
            if (LoadKey())
            {
                TbInputDecrypt.Text = ReadFile(CipherTextFileName);
            }
        }

        private void BtnSaveCipherText_OnClick(object sender, RoutedEventArgs e)
        {
            SaveKey();
            WriteFile(CipherTextFileName, TbInputDecrypt.Text);
        }

        private void WriteFile(string name, string text)
        {
            try
            {
                File.WriteAllText($"{Environment.CurrentDirectory}\\{name}", text);
            }
            catch
            {
                // ignored
            }
        }

        private string ReadFile(string name)
        {
            try
            {
                return File.ReadAllText($"{Environment.CurrentDirectory}\\{name}");
            }
            catch
            {
                return "";
            }
        }
    }
}