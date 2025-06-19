// @NUL0x4C | @mrd0x : MalDevAcademy
/*
	BaseNEncoder: Accepts an input payload file in raw format, encodes it using the Base-N algorithm, and outputs the encoded payload as a .BaseN file
*/

#include <Windows.h>
#include <stdio.h>
#pragma warning(disable : 4996)
//defines an extension for the output code with ".BaseN"
#define ENCODED_FILE  ".BaseN"

//Defined to execute a decoding example
//\
#define DECODE_EXAMPLE 
//------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// Reference:
// https://twitter.com/modexpblog/status/1637609530795204610
// https://gist.github.com/odzhan/5131fe34398129aca6ba67b5d3a3e4b4#file-base-cpp-L70

// Base value(5) used in encoding and decoding 
#define BASE_N 5
// Calculates the size of the encoded buffer 
#define CALC_ENC_SIZE(number) ((number + 4) / BASE_N * 8)
// Rounds up a given number to the nearest multiple of 5
#define ROUND_UP_TO_DIVISIBLE_BY_5(number) \
    ((number % 5 == 0) ? (number) : (((number) / 5) + 1) * 5)

/*
	- pInputBuffer		: Input buffer to encode/decode (is basically a raw binary data)
	- sInputSize		: Size of input buffer to encode/decode
	- ppOutputBuffer	: Pointer to a PBYTE, that is used to return the output buffer
	- psOutputSize		: Pointer to a SIZE_T, that is used to return the output buffer size
	- bEncode			: Flag to indicate whether the function should encode (if set to TRUE) or decode (if set to FALSE)
    - PBYTE : unassigned char** (points towards unassigned character)
    - HeapAlloc : Windows API Function for memory allocation, for Heap buffer.
*/
VOID BaseN(IN PBYTE pInputBuffer, IN SIZE_T sInputSize, OUT PBYTE* ppOutputBuffer, OUT PSIZE_T psOutputSize, IN BOOL bEncode) {

	// Checking input parameters for if the size is 0 or null.
	if (!pInputBuffer || !sInputSize || !ppOutputBuffer)
		return;
	// Setting initial value (is platform dependent 32 or 64 bits)
    // *psOutputSize : accesses the value stored at address pointed by psOutputSize which is a pointer to SIZE_T
	SIZE_T	sTmpSize = *psOutputSize = NULL;
	// If encode
	if (bEncode)
		*psOutputSize = sTmpSize = CALC_ENC_SIZE(ROUND_UP_TO_DIVISIBLE_BY_5(sInputSize));	// Calculate the size of the encoded buffer
	else
		*psOutputSize = sTmpSize = (BASE_N * sInputSize - (BASE_N * 8 - 4)) / 8;			// Calculate the size of the decoded buffer
		//It reverses the encoding size calculation.

	// Allocate heap buffer of the size calculated
    // Allocates memory dynamically using windows API 
    // HeapAlloc(): allocates memory from process heap
    // GetProcessHeap(): Gives access to the special memory called as 'default heap' where the memory is allocated.
    // HEAP_ZERO_MEMORY: is a flag which sends the signal to HeapAlloc to initialize all the located memory to zero.
	*ppOutputBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpSize);
	if (!*ppOutputBuffer)
		return;

	// Setting temporary variables
	unsigned char* puTmpOutputBuffer	= (unsigned char*)*ppOutputBuffer;
	unsigned char* puTmpInputBuffer		= (unsigned char*)pInputBuffer;

	// Variables initialized for decoding algorithm
	unsigned int	X	= 0, Z = 0;
	BYTE			WL	= 8, RL = BASE_N, MV = (1 << 8) - 1;

	// Re-initialize for encoding
	if (bEncode) {
		RL = 8;						// "Read length" is 8 bits for encoding
		WL = BASE_N;				// "Window length" is the specified BASE_N
		MV = (1 << BASE_N) - 1;		// "Mask value" is 2^BASE_N - 1
	}

	// Encoding/Decoding loop 
	//Processes the input buffer until the output buffer is filled.
	while (sTmpSize) {

		X = (X << RL) | *puTmpInputBuffer++;	// Shift input bits and append next byte
		Z += RL;								// Increment of the bit counter
		
		// Write output bytes when the bit counter reaches the "Window length"
		while (Z >= WL) {
			Z -= WL;									// Adjust the bit counter
			*puTmpOutputBuffer++ = (X >> Z /*dividing x by z times by 2*/ )& MV;		// Extract the bits and write to output buffer
			sTmpSize--;									// Decreasing the remaining size of the output buffer
		}
	}
}
//------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// Used to print the last error when Windows API fails 
// const char* ApiName: string input mostly the name of the API function of windows that failed. Like 'ReportError("HeapAlloc")'
// '%s' used as printf bcoz stores string name.
BOOL ReportError(const char* ApiName) {
	printf("[!] \"%s\" [ FAILED ] \t%d \n", ApiName, GetLastError());
	return FALSE;
} //  eg_output: [!] "HeapAlloc"	[ FAILED ]  8

// Read the input payload file into heap-allocated buffer and then returns the buffer with it's size.
// Here null is for default security not for empty space
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {

	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD FileSize = NULL;
	DWORD lpNumberOfBytesRead = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//hFile is like a pointer for a file thing here called as 'handle' 
	//this if is to check whether file can be opened or not.
	if (hFile == INVALID_HANDLE_VALUE) {
		return ReportError("CreateFileA");
	}
	// gets the file size in bytes
	FileSize = GetFileSize(hFile, NULL);

	//Allocates memory to store file contents with size decided by HeapAlloc which gets memory from Windows heap
	unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize);

    //fills the memory with 0s for making it clean
	ZeroMemory(Payload, FileSize);

	//reads the file into memory and reports error if fails.
	if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
		return ReportError("ReadFile");
	}

	//*pPayloadData ke address pe Payload ka content store hoga
	*pPayloadData = Payload;
	//*sPayloadSize is address to the pointer where size of content is stored.
	*sPayloadSize = lpNumberOfBytesRead;

	CloseHandle(hFile);

	//checks if the data and the size of the data is 0, if 0 then the file is not pointed to the correct path or memory asking from the windows heap might be encrypted.
	if (*pPayloadData == NULL || *sPayloadSize == NULL)
		return FALSE;

	return TRUE;
}

// Change the extension of the input file to become ENCODED_FILE (".BaseN").
char* ChangeFileExtension(char* fileName) {
	
	char* newFileName = (char*)malloc(strlen(fileName) + strlen(ENCODED_FILE) + 1);
	if (newFileName == NULL) {
		return NULL;
	}

	strcpy(newFileName, fileName);

	char* dot = (char*)strrchr(newFileName, '.');
	if (dot != NULL)
		*dot = '\0';

	strcat(newFileName, ENCODED_FILE);
	return newFileName;
}

// Write the encoded payload to a given file
BOOL WritePayloadFile(const char* FileInput, DWORD sPayloadSize, unsigned char* pPayloadData) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	lpNumberOfBytesWritten = NULL;

	hFile = CreateFileA(FileInput, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return ReportError("CreateFileA");


	if (!WriteFile(hFile, pPayloadData, sPayloadSize, &lpNumberOfBytesWritten, NULL) || sPayloadSize != lpNumberOfBytesWritten)
		return ReportError("WriteFile");

	CloseHandle(hFile);

	return TRUE;
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------------//

INT PrintHelp(IN CHAR* _Argv0) {

	printf("\t\t\t ##############################################################\n");
	printf("\t\t\t # BaseNEncoder - Designed By MalDevAcademy @NUL0x4C | @mrd0x #\n");
	printf("\t\t\t ##############################################################\n\n");

	printf("[!] Usage: %s <Payload FileName> \n", _Argv0);
	printf("\n\n[i] ");
	system("PAUSE");
	return -1;
}

#ifndef DECODE_EXAMPLE

// argv: argument vector - an array of strings (char*) containing the actual arguments
//argc: argument count - the number of command-line arguments
int main(int argc, char* argv[]) {

	//Checks if user provides correct number of arguments in bash.
	if (argc != 2) {
		return PrintHelp(argv[0]);
	}

	//points to the contents and size of the file.
	PBYTE	pPayloadInput = NULL;
	DWORD	dwPayloadSize = NULL;

	//!ReadPayloadFile: returns the value that indicates success or failure. i.e., 0 on success and non-zero on failure.(here)
	printf("[i] Reading \"%s\" ... ", argv[1]);
	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) 
	{
		return -1;
	}
	printf("[+] DONE \n");

	PBYTE		pCipherText = NULL;
	SIZE_T		sCipherSize = NULL;
	printf("[i] Encoding ... ");
	BaseN(pPayloadInput, dwPayloadSize, &pCipherText, &sCipherSize, TRUE);
	printf("[+] DONE \n");
	printf("\t> Encoded Buffer : 0x%p \n", pCipherText);
	printf("\t> Encoded Buffer Size : %d \n", sCipherSize);

	char* NewFileName = ChangeFileExtension(argv[1]);
	printf("[i] Writing Encoded Buffer To \"%s\" ...", NewFileName);
	if (!WritePayloadFile(NewFileName, sCipherSize, pCipherText)) {
		return -1;
	}
	printf("[+] DONE \n");

	// CleanUp
	HeapFree(GetProcessHeap(), 0, pCipherText);
	free(NewFileName);

	return 0;
}

#endif // !DECODE_EXAMPLE

//------------------------------------------------------------------------------------------------------------------------------------------------------------------//

#ifdef DECODE_EXAMPLE

//Encoded Shellcode is provided as a byte array. 
unsigned char EncodedMsfCalcShellcode[448] = {
	0x1F, 0x11, 0x04, 0x08, 0x07, 0x19, 0x07, 0x10, 0x1D, 0x03, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x05, 0x08, 0x14, 0x02, 0x14, 0x02, 0x12,
	0x0A, 0x05, 0x0B, 0x04, 0x10, 0x0C, 0x0E, 0x12, 0x0C, 0x15, 0x04, 0x08,
	0x16, 0x14, 0x13, 0x00, 0x09, 0x02, 0x05, 0x15, 0x04, 0x06, 0x02, 0x08,
	0x11, 0x0D, 0x09, 0x02, 0x00, 0x12, 0x04, 0x0B, 0x0E, 0x09, 0x08, 0x04,
	0x10, 0x03, 0x1D, 0x17, 0x09, 0x09, 0x05, 0x04, 0x1A, 0x0C, 0x0E, 0x09,
	0x09, 0x00, 0x18, 0x1C, 0x01, 0x0B, 0x01, 0x1C, 0x0C, 0x05, 0x1E, 0x00,
	0x04, 0x0B, 0x01, 0x00, 0x08, 0x07, 0x00, 0x1C, 0x12, 0x03, 0x0A, 0x01,
	0x00, 0x07, 0x00, 0x1E, 0x05, 0x1B, 0x0A, 0x12, 0x08, 0x05, 0x08, 0x14,
	0x11, 0x02, 0x1A, 0x12, 0x04, 0x02, 0x05, 0x14, 0x04, 0x0F, 0x02, 0x08,
	0x00, 0x07, 0x08, 0x08, 0x17, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x12, 0x04, 0x05, 0x18, 0x01, 0x1A, 0x06, 0x0E, 0x12, 0x00, 0x01,
	0x1A, 0x01, 0x08, 0x08, 0x16, 0x12, 0x00, 0x18, 0x08, 0x12, 0x05, 0x14,
	0x00, 0x08, 0x02, 0x09, 0x00, 0x07, 0x08, 0x0E, 0x06, 0x15, 0x12, 0x08,
	0x1F, 0x1F, 0x04, 0x14, 0x03, 0x02, 0x19, 0x14, 0x11, 0x01, 0x04, 0x00,
	0x03, 0x15, 0x12, 0x0D, 0x06, 0x07, 0x04, 0x14, 0x10, 0x0C, 0x0E, 0x00,
	0x15, 0x11, 0x00, 0x1C, 0x03, 0x12, 0x08, 0x0D, 0x08, 0x04, 0x00, 0x1C,
	0x02, 0x0E, 0x07, 0x00, 0x0E, 0x17, 0x18, 0x14, 0x18, 0x00, 0x1A, 0x0C,
	0x04, 0x10, 0x04, 0x04, 0x0A, 0x0E, 0x0E, 0x11, 0x0E, 0x17, 0x0C, 0x05,
	0x10, 0x11, 0x04, 0x0B, 0x08, 0x00, 0x12, 0x04, 0x12, 0x00, 0x0E, 0x10,
	0x0C, 0x19, 0x00, 0x18, 0x16, 0x03, 0x02, 0x08, 0x08, 0x12, 0x05, 0x14,
	0x00, 0x07, 0x02, 0x09, 0x00, 0x07, 0x08, 0x04, 0x03, 0x02, 0x18, 0x04,
	0x11, 0x01, 0x04, 0x00, 0x03, 0x14, 0x02, 0x01, 0x0B, 0x01, 0x00, 0x15,
	0x10, 0x17, 0x12, 0x19, 0x0B, 0x09, 0x00, 0x15, 0x10, 0x10, 0x0A, 0x19,
	0x08, 0x05, 0x0D, 0x04, 0x11, 0x00, 0x1F, 0x0C, 0x04, 0x01, 0x00, 0x15,
	0x05, 0x1F, 0x1F, 0x00, 0x0B, 0x01, 0x00, 0x15, 0x12, 0x16, 0x12, 0x08,
	0x11, 0x0C, 0x09, 0x0E, 0x12, 0x15, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F, 0x15,
	0x1A, 0x12, 0x05, 0x1A, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x04, 0x0D, 0x11, 0x14, 0x00, 0x10,
	0x02, 0x00, 0x00, 0x00, 0x08, 0x06, 0x1D, 0x03, 0x03, 0x02, 0x1B, 0x0F,
	0x10, 0x1F, 0x1F, 0x1D, 0x0B, 0x0E, 0x1F, 0x10, 0x16, 0x16, 0x11, 0x05,
	0x0C, 0x10, 0x0D, 0x1A, 0x14, 0x1A, 0x0A, 0x1B, 0x1B, 0x07, 0x0F, 0x1F,
	0x1A, 0x15, 0x04, 0x08, 0x07, 0x11, 0x01, 0x08, 0x07, 0x10, 0x03, 0x07,
	0x18, 0x02, 0x14, 0x00, 0x1F, 0x0F, 0x10, 0x07, 0x0A, 0x01, 0x0D, 0x1B,
	0x08, 0x1C, 0x09, 0x17, 0x04, 0x1B, 0x1B, 0x0A, 0x00, 0x01, 0x0C, 0x14,
	0x03, 0x02, 0x0E, 0x1A, 0x1F, 0x1F, 0x0A, 0x16, 0x06, 0x18, 0x0B, 0x0C,
	0x0C, 0x0C, 0x17, 0x06, 0x0A, 0x1E, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

VOID PrintHexData(PBYTE Data, SIZE_T Size) {

	printf(">>> Printing Raw Hex Data Of Size [ %d ]\n", Size);

	for (int i = 0; i < Size; i++) {
		
		if (i % 16 == 0) 
			printf("\n\t");

		if (i < Size - 1)
			printf("%0.2X ", Data[i]);
		else 
			printf("%0.2X ", Data[i]);
	}

	printf("\n\n");
}

//Calls '.BaseN' with 'bEncode = False' to decode the shellcode.
int main() {

	PBYTE	pRawBuffer	= NULL;
	SIZE_T	sRawSize	= NULL;

	BaseN(EncodedMsfCalcShellcode, sizeof(EncodedMsfCalcShellcode), &pRawBuffer, &sRawSize, FALSE);

	PrintHexData(pRawBuffer, sRawSize);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

#endif // DECODE_EXAMPLE