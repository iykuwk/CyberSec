#include <iostream>
#include <cstring>
#include <bitset>

using namespace std;

string Base32Encode(string& input)
{
    string Base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; //Base32 input 
    string binaryStr;
    for(char ch : input)
    {
        bitset<8> bits(ch); //8 bits per ch of Base32 (eg-11010101 into 5 stack then the forward process)
        binaryStr += bits.to_string();
    }

    int totalBits = binaryStr.size();
    int padBits = (5 - totalBits % 5) % 5; //remaining bits are added after subtracting from remaining unpaired 5 stack
    binaryStr.append(padBits, '0');

    string encoded;
    for(size_t i=0; i < binaryStr.size(); (i += 5))
    {
        bitset<5> chunk(binaryStr.substr(i, 5));
        encoded += Base32_chars[chunk.to_ulong()];
    }
    return encoded;
}
 
int main() {
    string input;
    cout<<"Enter the input to be converted: ";
    getline(cin, input);

    string Base32 = Base32Encode(input);
    cout<<"Base32 Encoded: "<<Base32<<endl;
    return 0;
}
