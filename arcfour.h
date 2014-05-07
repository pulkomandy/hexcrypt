/*********************************************************************
* Filename:   arcfour.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the ARCFOUR encryption algorithm.
              Algorithm specification can be found here:
               * http://en.wikipedia.org/wiki/RC4
*********************************************************************/

/*********************** FUNCTION DEFINITIONS ***********************/
void arcfour_key_setup(uint8_t state[], const uint8_t key[], int len)
{
	int i, j;
	uint8_t t;

	for (i = 0; i < 256; ++i)
		state[i] = i;
	for (i = 0, j = 0; i < 256; ++i) {
		j = (j + state[i] + key[i % len]) % 256;
		t = state[i];
		state[i] = state[j];
		state[j] = t;
	}
}

void arcfour_generate_stream(uint8_t state[], uint8_t out[], size_t len)
{
	int i, j;
	size_t idx;
	uint8_t t;

	for (idx = 0, i = 0, j = 0; idx < len; ++idx)  {
		i = (i + 1) % 256;
		j = (j + state[i]) % 256;
		t = state[i];
		state[i] = state[j];
		state[j] = t;
		out[idx] = state[(state[i] + state[j]) % 256];
	}
}
