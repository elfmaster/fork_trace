#include <stdio.h>

void f1(void)
{
	int i;
	int j = (int)&i;
	int x;

	if (j % 7 == 0)
		x = 5;
	else
		x = 9;
	return;
}
		
int main(void)
{
	int i;

	for (;;) {
		f1();
		for (i = 0; i < 10000000; i++)
			;
	}
}
