hexcrypt
========

Cipher and decipher data in intel ihex files.

The goal is to distribute encrypted firmware files that your bootloader will
decode (bootloader sold separately). This way, no one can know what's inside
your firmware.

Only the data is encrypted, leaving the addresses and checksums untouched. This
means a standard tool (eg. avrdude) can still use parse the file, only the
bootloader needs to be modified to decrypt the data on the fly.

This uses ARC4, which is a symmetric cipher. Make sure the flash on your
devices can't be read, otherwise people will find the key there and render the
whole scheme useless. An asymetric encoding would make things safer.
