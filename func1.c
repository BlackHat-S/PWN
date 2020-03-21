#include <stdio.h>
int func1 (){
    int a=0;
    scanf("%d",&a);
    return 1;
}
int main (){
    int a=0;
    a=func1();
    printf("%d",a);
    return 0;
}
