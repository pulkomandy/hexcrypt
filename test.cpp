#include "ihex.h"

#include <string.h>

void TEST(const char* message, bool result)
{
	const char* FAIL = "\x1B[31mFAIL\x1B[0m";
	const char* PASS = "\x1B[32mPASS\x1B[0m";

	printf(message);
	for(int i = strlen(message); i < 75; i++)
		putchar(' ');
	puts(result ? PASS : FAIL);
}

int main(void)
{
	IntelHex hex;
	IntelHex hex2;

	const uint8_t* key = (const uint8_t*)"I'm an unsafe key";

	TEST("Reading", hex.Read("tests/01.hex"));

	hex.Cipher(key, 18);
	hex2.Read("tests/01.hex");
	TEST("Ciphering", !(hex == hex2));

	TEST("Writing", hex.Write("tests/02.hex"));

	hex2.Read("tests/02.hex");
	TEST("Comparing", hex == hex2);

	hex2.Cipher(key, 18);
	hex.Read("tests/01.hex");
	TEST("Deciphering", hex == hex2);
}
