#include "ihex.h"

#include <stdlib.h>

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		std::cerr << argv[0] << " input.hex keyfile output.hex\n"
			"Encrypts or decrypts the data in an Intel Hex file.\n"
			"Addresses are unchanged, but checksum is updated.\n\n"
			"The [keyfile] is a raw binary file with the key data. The whole file is\n"
			"used as key data, and can be of arbitrary size.\n"
			;
		exit(-1);
	}

	IntelHex file;

	file.Read(argv[1]);

	std::ifstream keyfile;
	keyfile.open(argv[2], std::ios::in | std::ios::binary | std::ios::ate);

	if(!keyfile.is_open()) {
		std::cerr << "Error reading keyfile.\n";
		exit(-2);
	}

	keyfile.seekg(0, std::ios::end);
	int size = keyfile.tellg();
	keyfile.seekg(0, std::ios::beg);

	uint8_t key[size];
	keyfile.read((char*)key, size);
	file.Cipher(key, size);

	file.Write(argv[3]);
}
