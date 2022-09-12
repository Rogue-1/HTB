# SeeTheSharpFlag Writeup

### by ejedev

SeeTheSharpFlag is an easy mobile challenge from HackTheBox. 

To get started, we download the challenge and unzip it to see a file called `com.companyname.seethesharpflag-x86.apk`. As we would with any android app based challenge, let's take a look inside it to see what is going on.

We use `jadx-gui` to load the apk file and take a look.

![[Pasted image 20210809183307.png]]

Strangely, it doesn't look like most APK files. It's not a standard android application. We are unable to find the main activity, but do see some useful information: `xamarin.android.net`. 

I did some research and saw that it was a `.NET` framework for android development. The challenge name is making a lot more sense now. Upon further research, we see that we can dissasemble it quite easily using `ILSpy`.

First we use `apktool` to disassemble the APK file, you could also just extract it.

`apktool d com.companyname.seethesharpflag-x86.apk`

We find the DLL files we need inside `/com.companyname.seethesharpflag-x86/unknown/assemblies`

![[Pasted image 20210809183826.png]]

We want the DLL named after the application, and we see a `SeeTheSharpFlag.dll`.

Next we open up ILSpy and load that DLL.

![[Pasted image 20210809183958.png]]

We get an error. It looks like this isn't going to work out of the box. I did more research and found a python script to prep these files for disassembly.

https://github.com/x41sec/tools/blob/master/Mobile/Xamarin/Xamarin_XALZ_decompress.py

We save the file and get ready. We first rename the old DLL, then run the script against it and have it replace it.

![[Pasted image 20210809184217.png]]

We then open the new DLL with ILSpy and it works!

![[Pasted image 20210809184339.png]]

We take a quick look through and find something very interesting. under MainPage there is a button clicked event. Let's take a look at it.

```csharp
// SeeTheSharpFlag.MainPage
using System;
using System.IO;
using System.Security.Cryptography;
using Xamarin.Forms;

private void Button_Clicked(object sender, EventArgs e)
{
	//IL_0021: Unknown result type (might be due to invalid IL or missing references)
	//IL_0027: Expected O, but got Unknown
	//IL_0032: Unknown result type (might be due to invalid IL or missing references)
	//IL_0039: Expected O, but got Unknown
	//IL_003e: Unknown result type (might be due to invalid IL or missing references)
	//IL_0045: Expected O, but got Unknown
	//IL_0047: Unknown result type (might be due to invalid IL or missing references)
	//IL_004e: Expected O, but got Unknown
	byte[] array = Convert.FromBase64String("sjAbajc4sWMUn6CHJBSfQ39p2fNg2trMVQ/MmTB5mno=");
	byte[] array2 = Convert.FromBase64String("6F+WgzEp5QXodJV+iTli4Q==");
	byte[] array3 = Convert.FromBase64String("DZ6YdaWJlZav26VmEEQ31A==");
	AesManaged val = new AesManaged();
	try
	{
		ICryptoTransform val2 = ((SymmetricAlgorithm)val).CreateDecryptor(array2, array3);
		try
		{
			MemoryStream val3 = new MemoryStream(array);
			try
			{
				CryptoStream val4 = new CryptoStream((Stream)(object)val3, val2, (CryptoStreamMode)0);
				try
				{
					StreamReader val5 = new StreamReader((Stream)(object)val4);
					try
					{
						if (((TextReader)val5).ReadToEnd() == ((InputView)SecretInput).get_Text())
						{
							SecretOutput.set_Text("Congratz! You found the secret message");
						}
						else
						{
							SecretOutput.set_Text("Sorry. Not correct password");
						}
					}
					finally
					{
						((global::System.IDisposable)val5)?.Dispose();
					}
				}
				finally
				{
					((global::System.IDisposable)val4)?.Dispose();
				}
			}
			finally
			{
				((global::System.IDisposable)val3)?.Dispose();
			}
		}
		finally
		{
			((global::System.IDisposable)val2)?.Dispose();
		}
	}
	finally
	{
		((global::System.IDisposable)val)?.Dispose();
	}
}
```

This is quite long, mostly due to a lot of failsafe try blocks but it's a very simple decryption method written in C#. Let's modify this slightly and get the flag!

We remove a lot of redundant try/finally blocks as we only need it to work once, and end up with this:

```csharp
using System;
using System.Security.Cryptography;
using System.IO;
					
public class Program
{
	public static void Main()
	{
		Console.WriteLine("SeeTheSharpFlag writeup by ejedev");
		byte[] array = Convert.FromBase64String("sjAbajc4sWMUn6CHJBSfQ39p2fNg2trMVQ/MmTB5mno=");
	    byte[] array2 = Convert.FromBase64String("6F+WgzEp5QXodJV+iTli4Q==");
	    byte[] array3 = Convert.FromBase64String("DZ6YdaWJlZav26VmEEQ31A==");
	    AesManaged val = new AesManaged();
		ICryptoTransform val2 = ((SymmetricAlgorithm)val).CreateDecryptor(array2, array3);
		MemoryStream val3 = new MemoryStream(array);
		CryptoStream val4 = new CryptoStream((Stream)(object)val3, val2, (CryptoStreamMode)0);
		StreamReader val5 = new StreamReader((Stream)(object)val4);
		Console.WriteLine(((TextReader)val5).ReadToEnd());
	}
}
```

We run it and get the following output:

```
SeeTheSharpFlag writeup by ejedev  
HTB{MXXXXXXXXXXXXXXXXXXXXX}
```

*Flag redacted for obvious reasons.*

That's it! We got the flag.