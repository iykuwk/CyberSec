#include <iostream>
#include <cstring>
using namespace std;

void bufferOF(char* input) //input as a pointer to character.
{
    char buffer[10]; //assigning 10 characters for string.
    strcpy(buffer, input);
    cout<<buffer<<endl;
}
int main()
{
    char userinput[50];
    cout<<"Enter OverFlow string: ";
    cin>>userinput;
    
    bufferOF(userinput); //calls 'userinput' and copies string data unsafely
    if(strlen(userinput) >= 10){
        cout<<"HAHAHAHAHA"; //if the bufferinput is >10 characters
    }
    else{
        cout<<userinput;
    }
     return 0;
}