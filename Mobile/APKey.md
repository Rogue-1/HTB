### Challenge: APKey

### Type: Mobile

### Tools: apktool, jadx-gui, android studio, visual studio


Since pwnbox does not natively come with important Moible challenge tools I had to install a few to finish this challenge. 

```console
└──╼ [★]$ Sudo apt install jadx
└──╼ [★]$ jadx-gui
```
Starting off, if we open the program in jadx-gui we can see we have a username ```admin``` it is encrypted with md5 and we have an encrypted string.

All we have to do is change that encrypted string to one that we create.

![image](https://user-images.githubusercontent.com/105310322/189731859-fc60ce5e-e137-4cb7-bc2e-7a743edeaf76.png)


Here I am creating an md5 hash of the word pass.

```console
└──╼ [★]$ echo 'pass' | md5sum
4528e6a7bb9341c36c425faf40ef32c3
```

Next I am going to decompile the apk file with apktool

```console
└──╼ [★]$ Sudo apt install apktool
└──╼ [★]$ apktool d APKey.apk
```

Next we are going to open the decompiled APKey folder in Visual Studio and install the APKlab extension (follow the directions in the APKlab extension)

Here is the classes.dex that contains the info we are going to overwrite.

I find the old hash and overwrite with ```const-string v1, "4528e6a7bb9341c36c425faf40ef32c3"```

```c
.class public Lcom/example/apkey/MainActivity$a;
.super Ljava/lang/Object;
.source ""

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/example/apkey/MainActivity;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic b:Lcom/example/apkey/MainActivity;


# direct methods
.method public constructor <init>(Lcom/example/apkey/MainActivity;)V
    .locals 0

    iput-object p1, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 4

    :try_start_0
    iget-object p1, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

    iget-object p1, p1, Lcom/example/apkey/MainActivity;->c:Landroid/widget/EditText;

    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    const-string v0, "admin"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    iget-object p1, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

    iget-object v1, p1, Lcom/example/apkey/MainActivity;->e:Lc/b/a/b;

    iget-object p1, p1, Lcom/example/apkey/MainActivity;->d:Landroid/widget/EditText;

    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    :try_start_1
    const-string v1, "MD5"

    .line 1
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/String;->getBytes()[B

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/security/MessageDigest;->update([B)V

    invoke-virtual {v1}, Ljava/security/MessageDigest;->digest()[B

    move-result-object p1

    new-instance v1, Ljava/lang/StringBuffer;

    invoke-direct {v1}, Ljava/lang/StringBuffer;-><init>()V

    const/4 v2, 0x0

    :goto_0
    array-length v3, p1

    if-ge v2, v3, :cond_0

    aget-byte v3, p1, v2

    and-int/lit16 v3, v3, 0xff

    invoke-static {v3}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    move-result-object p1
    :try_end_1
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_1

    :catch_0
    move-exception p1

    :try_start_2
    invoke-virtual {p1}, Ljava/security/NoSuchAlgorithmException;->printStackTrace()V

    const-string p1, ""

    :goto_1
    const-string v1, "4528e6a7bb9341c36c425faf40ef32c3"

    .line 2
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

    invoke-virtual {p1}, Landroid/app/Activity;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iget-object v0, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

    iget-object v1, v0, Lcom/example/apkey/MainActivity;->e:Lc/b/a/b;

    iget-object v0, v0, Lcom/example/apkey/MainActivity;->f:Lc/b/a/g;

    invoke-static {}, Lc/b/a/g;->a()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lc/b/a/b;->a(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x1

    invoke-static {p1, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    :goto_2
    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    goto :goto_3

    :cond_1
    iget-object p1, p0, Lcom/example/apkey/MainActivity$a;->b:Lcom/example/apkey/MainActivity;

    invoke-virtual {p1}, Landroid/app/Activity;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string v1, "Wrong Credentials!"

    invoke-static {p1, v1, v0}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    goto :goto_2

    :catch_1
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Exception;->printStackTrace()V

    :goto_3
    return-void
.end method
```
Next we need to rebuild the APK.

No matter what I did I was unable to rebuild the apk using this command that would normally work. However apktool uses aapt so I tested that out instead.

However running the ```apktool b``` command still rebuilt the classes.dex. So with that we can use aapt to fix the orignial apk.

```console
└──╼ [★]$ apktool b APKey -o APKey1.apk
I: Using Apktool 2.5.0-dirty
I: Checking whether sources has changed...
I: Checking whether resources has changed...
I: Building resources...
W: aapt: brut.common.BrutException: brut.common.BrutException: Could not extract resource: /prebuilt/linux/aapt_64 (defaulting to $PATH binary)
W: res/drawable/$avd_hide_password__0.xml: Invalid file name: must contain only [a-z0-9_.]
W: res/drawable/$avd_hide_password__1.xml: Invalid file name: must contain only [a-z0-9_.]
W: res/drawable/$avd_hide_password__2.xml: Invalid file name: must contain only [a-z0-9_.]
W: res/drawable/$avd_show_password__0.xml: Invalid file name: must contain only [a-z0-9_.]
W: res/drawable/$avd_show_password__1.xml: Invalid file name: must contain only [a-z0-9_.]
W: res/drawable/$avd_show_password__2.xml: Invalid file name: must contain only [a-z0-9_.]
W: res/drawable-anydpi-v24/$ic_launcher_foreground__0.xml: Invalid file name: must contain only [a-z0-9_.]
brut.androlib.AndrolibException: brut.common.BrutException: could not exec (exit code = 1): [aapt, p, --min-sdk-version, 16, --target-sdk-version, 30, --version-code, 1, --version-name, 1.0, --no-version-vectors, -F, /tmp/APKTOOL11251881523701162891.tmp, -0, resources.arsc, -0, png, -0, arsc, -I, /home/htb-0xrogue/.local/share/apktool/framework/1.apk, -S, /home/htb-0xrogue/Downloads/APKey/res, -M, /home/htb-0xrogue/Downloads/APKey/AndroidManifest.xml]
```

I ran this command which seemed to work.

```
└──╼ [★]$ aapt add -v APKey.apk APKey/build/apk/classes.dex
 'APKey/build/apk/classes.dex'...
```

Now I can confirm I have overwritten the MD5sum with my own!

![image](https://user-images.githubusercontent.com/105310322/189737121-e8319b49-3828-467f-a573-76bbaf83fdf4.png)


If apktool b APKey -o APKey1 would have worked before than I still would have had to create a key and then sign it with the following commands.

```
└──╼ [★]$ keytool -genkey -v -keystore mykey.keystore -alias APKey1 -keyalg RSA -keysize 2048 -validity 1000
└──╼ [★]$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore mykey.keystore APKey1.apk APKey1
```

All thats left is to run the new program with an emulator such as Android studio and login with the password you created with the MD5 hash to get the flag!
