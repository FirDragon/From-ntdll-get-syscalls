#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <math.h>
#include <Windows.h>

#define B(x) (x/8)

static unsigned char MD5Encriptor(unsigned char* bytes, unsigned int size, unsigned char* output, unsigned int outputSize);
int main()
{
	unsigned char byte[56] = "123456";
	unsigned char output[B(512)];

	
	PROCESS_ALL_ACCESS;//
	if (!MD5Encriptor(byte, sizeof(byte), output, 512 / 8))
		printf("encrypt failed!\n");
	printf("Pass!\n");
	return 0;
}

#define F(x,y,z)			(((x)&(y))|((x)&(z)))
#define G(x,y,z)			(((x)&(z))|((y)&(x)))
#define H(x,y,z)			((x)^(y)^(z))
#define I(x,y,z)			((y)^((x)|(z)))
#define T(i)				(4294967296*abs(sin(i)))

unsigned char MD5Encriptor(unsigned char* bytes,unsigned int size, unsigned char* output, unsigned int outputSize)
{
	unsigned char* map;
	map = makeMap(bytes, size, output, outputSize);
	if (!map)
		return 0;



	return 1;
}
unsigned char* SegConvert(unsigned char* seg)
{
	unsigned int segMap[4] = {
		0x01234567, 
		0x89abcdef,
		0xfedcba98,
		0x76543210
	};

	return 0;
}
unsigned char* makeMap(unsigned char* bytes, unsigned int size, unsigned char* output, unsigned int outputSize)
{
	int len;
	int c = B(448) - size % B(512);
	unsigned char* map;
	if (!c)
		c += B(512);
	len = size + c;

	map = (unsigned char*)malloc(len);
	if (!map)
		return 0;

	memcpy(map, bytes, size);
	memset(map + size, 0, c);
	if (c == B(512))
		map[size] = 1;


	*(((__int64*)&map[len]) - 1) = size;
	return map;
}