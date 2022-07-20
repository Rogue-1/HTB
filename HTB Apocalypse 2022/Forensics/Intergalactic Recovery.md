# Intergalactic Recovery

### Challenge: Forensics

### Tools: Python, Mounting

### Description: Miyuki's team stores all the evidence from important cases in a shared RAID 5 disk. Especially now that the case IMW-1337 is almost completed, evidences and clues are needed more than ever. Unfortunately for the team, an electromagnetic pulse caused by Draeger's EMP cannon has partially destroyed the disk. Can you help her and the rest of team recover the content of the failed disk?

After downloading the files we can see that we have 3 images. 1 of the files is corrupted as can be seen by the low amount of bytes. The description of the challenge tells us we need to recover a Raid 5 disk. The only way to do this is to Xor the other 2 images that are not corrupted. If there was more than 1 corrupted disk we would not be able to recover the data.




With this script that I borrowed from Crypto-Cat we can easily Xor the 2 images to recover the 3rd.
Make note of what is written next to disk 1 and 3. If you do not Xor these disks properly then the recovered disk will still be corrupted and the data from the mounted image will not be able to be accessed.




After the Xoring we can type the following commands to mount a Raid 5 array and access it.

```console
sudo losetup /dev/loop1 disk1.img
sudo losetup /dev/loop2 disk2.img
sudo losetup /dev/loop3 disk3.img

sudo mdadm --create --level=5 --raid-devices=3 /dev/md0 /dev/loop1 /dev/loop2 /dev/loop3
sudo mkdir /mnt/IRraid
sudo mount /dev/md0 /mnt/IRraid
ls /mnt/IRraid
```

The contents of the full disk image holds a PDF file with our flag!


GG.
