#include <stdio.h>

int main(void)
{
	int i;
	srand(10);
	for (i = 0; i < 10; i++)
		printf("%d\n", rand());
}
