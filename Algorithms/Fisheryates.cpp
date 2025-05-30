#include <iostream>
#include <vector> //provides faster random access to memory location.
#include <ctime> //date and time handling like randomness of data by 'vector' w.r.t time by 'ctime'
#include <chrono> //better alternative for 'ctime'. Provides high precision time handlings.
#include <cstdlib> //for rand() and srand(): generating and seeding for random numbers.

using namespace std;

void fisherYS(vector<int>& arr)
{
    int n = arr.size();
    //seeds random number generator with current time
    srand(static_cast<unsigned int>(time(0)));

    //fisher yates algorithm
    for(int i= n-1; i>0; --i)
    {\
        
        int j = rand() % (i+1); //random number generation from 0 to i

        swap(arr[i], arr[j]); //swaping i with j array
    }
}

int main(){
    vector<int> arr = {1,2,3,4,5,6,7,8,9,10};
    cout<<"Original Array: ";
    for(int num: arr)
    cout<<num<<" ";
    cout<<endl;

    fisherYS(arr);

    cout<<"Shuffled Array: ";
    for(int num : arr)
    cout<<num<<" ";
    cout<<endl;
    return 0;
}