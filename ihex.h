/* HexCrypt - Encrypt and decrypt data in intel hex files.
 * Copyright 2014, Adrien Destugues <pulkomandy@pulkomandy.tk>
 * This program is distributed under the terms of the MIT licence.
 */

#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "arcfour.h"

/// ParseError exception, for internal use.
/// Just a standard C++ exception with a text error message.
class ParseError: public std::exception
{
	public:
		ParseError(const int line, const int column, const char* message, const char* data)
			: std::exception()
			, fMessage("Parse error at ")
		{
			std::ostringstream stream;
			stream << "Parse error at " << line << ":" << column << ": " << message << std::endl;
			stream << data << std::endl;
			for(int i = 0; i < column; i++)
				stream << ' ';
			stream << '^';
			fMessage = stream.str();
		}

		const char* what() const noexcept {
			return fMessage.c_str();
		}

	private:
		std::string fMessage;
};


class HexRecord {
	public:
		HexRecord(uint8_t* data) {
			size = data[0];
			address = (data[1] << 8) | data[2];
			type = data[3];
			checksum = data[size + 4];
			this->data.assign(&data[4], &data[size + 4]);
		}

		void Generate(std::ostream& output) const throw(std::ios_base::failure);

		bool operator==(const HexRecord& other) const {
			if (size != other.size) return false;
			if (address != other.address) return false;
			if (type != other.type) return false;
			if (checksum != other.checksum) return false;
			return true;
		}

		void UpdateChecksum() {
			checksum = size + (address >> 8) + (address & 0xff) + type;
			for(uint8_t i: data) {
				checksum += i;
			}
			checksum = -checksum;
		}

	private:
		uint8_t size;
		uint16_t address;
	public:
		uint8_t type;
		std::vector<uint8_t> data;
	private:
		uint8_t checksum;
};


void HexRecord::Generate(std::ostream& output) const throw(std::ios_base::failure)
{
	output << ':';

	uint8_t buffer[size + 5];
	buffer[0] = size;
	buffer[1] = address >> 8;
	buffer[2] = address;
	buffer[3] = type;

	for(int i = 0; i < size; i++)
	{
		buffer[i + 4] = data[i];
	}

	buffer[size + 4] = checksum;

	for(int i = 0; i < size + 5; i++)
	{
		char n1, n2;
		n1 = buffer[i] >> 4;
		n2 = buffer[i] & 0xF;

		if (n1 < 10)
			n1 += '0';
		else
			n1 += 'A' - 10;

		if (n2 < 10)
			n2 += '0';
		else
			n2 += 'A' - 10;

		output << n1 << n2;
	}

	output << "\r\n";
}




/// Read and write Intel hex format files.
class IntelHex {
	public:
		bool Read(const char* filename);
		bool Write(const char* filename);

		void Cipher(const uint8_t* key, int len);
			// ARC4 is symmetric, so this also deciphers.

		bool operator==(const IntelHex& other) { return fData == other.fData; }

	private:
		void Parse(std::istream& input) throw(std::ios_base::failure, ParseError);
		void Generate(std::ostream& output) throw(std::ios_base::failure);
		void WriteRecord(std::ostream& output, const uint8_t type, const uint16_t address,
			const std::vector<uint8_t> data) throw(std::ios_base::failure);

		std::vector<HexRecord> fData;
};


/// Read and parse an intel ihex file
/// @filename name of the file to read
/// @returns true on success, false on error.
bool IntelHex::Read(const char* filename)
{
	std::ifstream file;
	// Configure the object to throw exceptions, so we can catch them
	file.exceptions(std::ifstream::failbit | std::ifstream::badbit);

	try {
		file.open(filename);
		Parse(file);
		return true;
	} catch(std::ios_base::failure e) {
		std::cerr << "Can't read input file: " << e.what() << std::endl;
		return false;
	} catch(ParseError e) {
		std::cerr << e.what() << std::endl;
		return false;
	}
}


/// Write the data to an ihex file.
bool IntelHex::Write(const char* filename)
{
	std::ofstream file;
	// Configure the object to throw exceptions, so we can catch them
	file.exceptions(std::ifstream::failbit | std::ifstream::badbit);

	try {
		file.open(filename);
		Generate(file);
		return true;
	} catch(std::ios_base::failure e) {
		std::cerr << "Can't write output file: " << e.what() << std::endl;
		return false;
	}
}


/// Parse intel hex data from input stream.
/// Will throw exceptions on errors reading the file.
void IntelHex::Parse(std::istream& input) throw(std::ios_base::failure, ParseError)
{
	fData.clear();
	uint32_t extended = 0;

	for(int l = 1; true; l++) {
		char line[1026];
		uint8_t buffer[512];

		// Read line from file
		input.getline(line, sizeof(line));
		std::streamsize length = input.gcount() - 1;
			// - 1 because the \n is replaced with the NULL char.

		if (length < 10 || line[0] != ':')
			throw ParseError(l, 0, "not starting with ':' or too short", line);

		// Convert line to bytes
		int byte = 0;
		uint8_t sum = 0;
		for(int i = 1; i < length ; i ++) {
			uint8_t nibble = line[i];
			if (nibble >= '0' && nibble <= '9')
				nibble -= '0';
			else if (nibble >= 'a' && nibble <= 'f')
				nibble -= 'a' - 10;
			else if (nibble >= 'A' && nibble <= 'F')
				nibble -= 'A' - 10;
			else if (nibble == '\r' && i == length - 1)
				break; // Ignore end of line char
			else
				throw ParseError(l, i, "not an hexadecimal character", line);

			if (i & 1) {
				// First nibble for current byte
				buffer[byte] = nibble;
			} else {
				// Second nibble for current byte
				buffer[byte] <<= 4;
				buffer[byte] |= nibble;

				sum += buffer[byte];
				++byte;
			}
		}

		if (sum != 0)
			throw ParseError(l, length - 2, "checksum error", line);

		uint8_t count = buffer[0];

		if (count + 5 != byte)
			throw ParseError(l, 2, "mismatched length", line);

		HexRecord r = HexRecord(buffer);
		fData.push_back(r);
		if (r.type == 1)
			return;
	}
}


void IntelHex::Generate(std::ostream& output) throw(std::ios_base::failure)
{
	for (auto line: fData)
	{
		// Write data record
		line.Generate(output);
	}
}


void IntelHex::Cipher(const uint8_t* key, int len)
{
	uint8_t state[256];

	arcfour_key_setup(state, key, len);

	// There is a known attack on ARC4 allowing to recover the key from:
	// - An unencrypted message
	// - The matching first 256 bytes of encrypted data
	// Skipping the first 256 bytes of the keystream avoids this. Of course the
	// decoder must do the same.
	uint8_t stream[256];
	arcfour_generate_stream(state, stream, 256);

	for (auto& line: fData)
	{
		arcfour_generate_stream(state, stream, line.data.size());
		for(int i = 0; i < line.data.size(); i++) {
			line.data[i] ^= stream[i];
		}
		line.UpdateChecksum();
	}
}
