#include <Windows.h>
#include <stdio.h>

// Defining a USTRING struct
// This is what SystemFunction033 function take as parameters instead of SystemFucntion032
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

// Defining how does the SystemFunction033 function look. 
// More on this structure in the API Hashing module
typedef NTSTATUS(NTAPI* fnSystemFunction033)(
	struct USTRING* Data,
	struct USTRING* Key
	);

BOOL Rc4EncryptionViaSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// The return of SystemFunction033
	NTSTATUS	STATUS = NULL;

	// Making 2 USTRING variables
	// 1 is passed as the key and the other one is passed as the block of data to encrypt/decrypt
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
				Data = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };


	// Since SystemFunction033 is exported from Advapi32.dll, use LoadLibraryA to load Advapi32.dll into the process, 
	// And use LoadLibraryA's return value as the hModule parameter in GetProcAddress
	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	// If the SystemFunction033 invocation failed, it will return a non-zero value 
	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

//Made the code userinput handling for both text and key for encryption and decryption.
int main() {
	char userinput[256];
	char rc4Key[256];
	DWORD inputLength, keyLength;

	printf("[+] Enter a string to encrypt: ");
	fgets(userinput, sizeof(userinput), stdin);
	inputLength = strlen(userinput);
	if (userinput[inputLength - 1] == '\n') 
	{
		userinput[inputLength - 1] = '\0'; //removes new line added
		inputLength--;
	}

	printf("[+] Enter an RC4 key (any string): ");
	fgets(rc4Key, sizeof(rc4Key), stdin);
	keyLength = strlen(rc4Key);
	if (rc4Key[keyLength - 1] == '\n') {
		rc4Key[keyLength - 1] = '\0';  // Remove newline
		keyLength--;
	}

	printf("\n[i] Original string: \"%s\" (Length: %d)\n", userinput, inputLength);
	printf("[i] RC4 Key: \"%s\" (Length: %d)\n", rc4Key, keyLength);

	// Encryption
	printf("\n[#] Encrypting...\n");
	if (!Rc4EncryptionViaSystemFunc033((PBYTE)rc4Key, (PBYTE)userinput, keyLength, inputLength)) {
		return -1;
	}
	printf("[+] Encrypted data (hex): ");
	for (DWORD i = 0; i < inputLength; i++) {
		printf("%02X ", (unsigned char)userinput[i]);
	}
	printf("\n");

	// Decryption
	printf("\n[#] Press <Enter> to Decrypt..."); // we use '[#]' when user interaction is required & r known as logging conventions
	getchar();

	printf("[#] Decrypting...\n");
	if (!Rc4EncryptionViaSystemFunc033((PBYTE)rc4Key, (PBYTE)userinput, keyLength, inputLength)) {
		return -1;
	}
	printf("[+] Decrypted string: \"%s\"\n", userinput); // we use '[+]' for success/positive action & r known as logging conventions

	printf("\n[#] Press <Enter> to Exit...");
	getchar();

	return 0;
}
