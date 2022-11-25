#include <algorithm>
#include <iostream>
#include <vector>
#include <string>

using namespace std;


int main() {
    int n,h;
    int ans=0;
    cin>>n;
    cin>>h;
    for(int i=0;i<n;i++){
        int temp;
        cin>>temp;

        if(temp>0&&temp<=2*h){
            if(temp>h){
                ans +=2;
            }
            else{
                ans +=1;
            }
        }
    }
    cout<<ans;

	return 0;
  }
