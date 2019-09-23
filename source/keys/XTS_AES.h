
// 암호화 모드
#define ENC 1 
// 복호화 모드
#define DEC 0 

typedef unsigned char BYTE;

// 128비트 XTS_AES 암복호화 인터페이스
void XTS_AES128(BYTE *plain, BYTE *cipher, unsigned int size, BYTE* key, int mode);