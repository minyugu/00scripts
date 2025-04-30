cd /Applications/Genymotion.app/Contents/MacOS/tools/
./adb connect 127.0.0.1:6555
./adb root
./adb shell

su
mount -o rw,remount /

ls /dev/block/dm-0

ls /storage/emulated
dd if=/dev/block/by-name/boot of=/sdcard/boot.img

ls /dev/block/by-name/boot

ls -al /dev/block/by-name

dd if=/dev/block/by-name/system of=/sdcard/Download/sys.img

cat /proc/partitions

dd if=/dev/block/vda2 of=/sdcard/boot.img bs=4096