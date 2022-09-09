### Challenge: Cat

### Type: Mobile


Android Studio is not needed but I added the link for later reference since I just started doing Mobile challenges. Tried using it in another challenge but it wasn't needed either. However I think It ill be useful in the future.

https://wiki.debian.org/AndroidStudio


This link was nescessary to unpack the .ab file and read the contents of the backup.

Note: ADB is a toolkit for Android that also had an exploit where you could remote into it and gain access to a victims phone.

https://sourceforge.net/projects/android-backup-toolkit/

After Downloading navigate to your folder and start unpacking.

```
┌─[us-dedivip-1]─[10.10.14.53]─[htb-0xrogue@pwnbox-base]─[~/Downloads/android-backup-tookit/android-backup-processor/executable]
└──╼ [★]$ java -jar abp.jar unpack ~/Downloads/cat.ab ~/Downloads/cat.zip
```

Just accessing the zip file reveals a few empty directories except for the pictures.

So many cute pictures of cats!

![image](https://user-images.githubusercontent.com/105310322/189455745-939cbfac-6eb8-4d23-94fd-35ae863826c6.png)


Except 1 that shows a man holding a Top Secret file written in an unreadable language!!!!

![image](https://user-images.githubusercontent.com/105310322/189455787-b9b110e8-858b-4566-a0b2-c8ea677d7df0.png)

But our flag is very readable ;)

![image](https://user-images.githubusercontent.com/105310322/189455814-e95a6769-271f-4bd1-b315-cc75c593c670.png)
