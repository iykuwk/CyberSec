#include <iostream>
#include <cstring>
#include <vector>
using namespace std;

//function for encryption and decryption by xor method.
string xorED(const string& input, const string& key) 
{
    string output;
    output.resize(input.size());
    
    for (size_t i = 0; i < input.size(); ++i) {
        // XOR of each character of input with corresponding key character
        // If key is shorter than input, wrap around using '%': meaning repeat the key if insufficient
        // Plaintext: HELLO but Key: KEYKE, therefore repeates itself till the stringsize of the plaintext.
        output[i] = input[i] ^ key[i % key.size()];//algorithm formula for conversion to binary, w.r.t. key.
    }
    
    return output;
}

// Function to display string as hexadecimal
void displayHex(const string& str)
{
    for (unsigned char c : str) 
    {
        cout<<hex<<(int)c<<" ";
    }
    cout<<dec<<endl; // Reset to decimal
}

int main() 
{
    string plaintext, key;
    
    cout<<"Enter plaintext: ";
    getline(cin, plaintext);
    
    cout<<"Enter encryption key: ";
    getline(cin, key);
    
    if (key.empty()) 
    {
        // cerr: displays character error or used to display warnings.
        cerr<<"Error: Key cannot be empty!" << endl;
        return 1;
    }
    
    string ciphertext = xorED(plaintext, key);
    
    cout << "\nOriginal plaintext: " << plaintext << endl;
    cout << "Plaintext in hex: ";
    displayHex(plaintext);
    
    cout << "\nCiphertext: " << ciphertext << " (non-printable characters may not display)" << endl;
    cout << "Ciphertext in hex: ";
    displayHex(ciphertext);

    string decrypted = xorED(ciphertext, key);
    
    cout << "\nDecrypted text: " << decrypted << endl;
    cout << "Decrypted in hex: ";
    displayHex(decrypted);
    
    if (plaintext == decrypted) 
    {
        cout << "\nSuccess! Plaintext and decrypted text match." << endl;
    } 
    else 
    {
        cout << "\nError! Plaintext and decrypted text don't match." << endl;
    }
    return 0;
}