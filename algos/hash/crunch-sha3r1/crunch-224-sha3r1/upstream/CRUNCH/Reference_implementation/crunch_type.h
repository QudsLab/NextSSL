typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

typedef struct 
{
	int hashbitlen;
} hashState;


#ifdef M64
typedef unsigned long long BlockType;
#else
typedef unsigned int BlockType;
#endif

