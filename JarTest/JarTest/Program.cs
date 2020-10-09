using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JarTest
{
	class Program
	{
		static void Main(string[] args)
		{
			ZipFile.ExtractToDirectory("D:\\Test.Jar", "D:\\JarTest");
		}
	}
}
