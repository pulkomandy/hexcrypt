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

		std::map<uint32_t, std::vector<uint8_t> > fData;
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

		uint16_t offset = (buffer[1] << 8) | buffer[2];
		uint8_t type = buffer[3];

		switch(type)
		{
			case 0: // data
			{
				std::pair<uint32_t, std::vector<uint8_t> > record;
				record.first = extended | offset;
				record.second = std::vector<uint8_t>(&buffer[4], &buffer[4 + count]);
				fData.insert(record);
				break;
			}
			case 1: // end of file
				if (count != 0)
					throw ParseError(l, 9, "end-of-file record has data", line);
				return;
			case 4: // extended linear address
				if (count != 2)
					throw ParseError(l, 9, "wrong size for extended address record", line);
				extended = (buffer[4] << 24) | (buffer[5] << 16);
				break;
			default:
				throw ParseError(l, 8, "unhandled record type", line);
		}
	}
}


void IntelHex::Generate(std::ostream& output) throw(std::ios_base::failure)
{
	uint32_t extended = 0;
	for (auto line: fData)
	{
		if ((line.first & 0xffff0000) != extended)
		{
			// Write extended linear address record
			std::vector<uint8_t> xaddr;
			xaddr.push_back(line.first >> 24);
			xaddr.push_back(line.first >> 16);
			WriteRecord(output, 4, 0, xaddr);

			extended = line.first & 0xffff0000;
		}

		// Write data record
		WriteRecord(output, 0, line.first, line.second);
	}

	// Write end record
	const std::vector<uint8_t> empty;
	WriteRecord(output, 1, 0, empty);
}


void IntelHex::WriteRecord(std::ostream& output, const uint8_t type, const uint16_t address,
	const std::vector<uint8_t> data) throw(std::ios_base::failure)
{
	output << ':';

	const int length = data.size();

	uint8_t buffer[length + 5];
	buffer[0] = length;
	buffer[1] = address >> 8;
	buffer[2] = address;
	buffer[3] = type;

	for(int i = 0; i < length; i++)
	{
		buffer[i + 4] = data[i];
	}

	buffer[length + 4] = 0;

	for(int i = 0; i < length + 5; i++)
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
		buffer[length + 4] -= buffer[i];
	}

	output << "\r\n";
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
		arcfour_generate_stream(state, stream, line.second.size());
		for(int i = 0; i < line.second.size(); i++) {
			line.second[i] ^= stream[i];
		}
	}
}
