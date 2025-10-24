#include <iostream>
#include <string>
#include <bitset>
#include <iomanip>
#include <locale>
#include <codecvt>
#include <sstream> // For ostringstream

using namespace std;

// Convert 16-bit value to binary string
string toBinary(uint16_t value) {
    return bitset<16>(value).to_string();
}

// Format code point as U+XXXX (hex, uppercase, zero-padded)
string formatCodePoint(uint16_t value) {
    ostringstream oss;
    oss << "U+" << hex << uppercase << setw(4) << setfill('0') << value;
    return oss.str();
}

// Format hex output as 0xXXXX
string formatHex(uint16_t value) {
    ostringstream oss;
    oss << "0x" << hex << uppercase << setw(4) << setfill('0') << value;
    return oss.str();
}

int main() {
    // Input string
    string input;
    cout << "Enter a string to encode in UTF-16: ";
    getline(cin, input);

    // UTF-8 to UTF-16 converter
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> converter;
    u16string utf16_string;

    try {
        utf16_string = converter.from_bytes(input);
    } catch (const range_error& e) {
        cerr << "Error: Invalid UTF-8 input. Please enter valid characters." << endl;
        return 1;
    }

    // Output header with adjusted widths for better alignment
    cout << "\nUTF-16 Encoding for \"" << input << "\":\n";
    cout << left
         << setw(12) << "Character"
         << setw(18) << "UTF-16 Code Unit"
         << setw(20) << "Binary"
         << setw(10) << "Decimal"
         << "Hexadecimal" << "\n";
    cout << string(72, '-') << "\n";

    // Process each UTF-16 code unit
    for (size_t i = 0; i < utf16_string.length(); ++i) {
        char16_t code_unit = utf16_string[i];
        uint16_t value = static_cast<uint16_t>(code_unit);

        // Get display character, handling surrogates and non-printables
        string display_char;
        try {
            display_char = converter.to_bytes(u16string(1, code_unit));
            if (display_char.empty() || 
                (display_char.size() == 1 && static_cast<unsigned char>(display_char[0]) < 32)) {
                display_char = "<non-printable>";
            }
        } catch (const range_error& e) {
            display_char = "<surrogate>";
        }

        // Output with consistent formatting, resetting stream state
        cout << left
             << setw(12) << display_char
             << setw(18) << formatCodePoint(value)
             << setw(20) << toBinary(value)
             << setw(10) << dec << value
             << formatHex(value) << "\n";
    }

    // Reset cout to default state
    cout << dec << setfill(' ');
    return 0;
}