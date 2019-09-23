/*  ============================================================================================================ *
    2012036901 - 윤진한
                                    주 의 사 항


    1. 주석으로 표현된 구현 블록 13에서 14번까지 구현하여 128비트 AES 암호화 알고리즘을 구현해야 함
    2. AES.c를 먼저 구현한 다음, 해당 파일을 구현함
    3. 사전에 주어진 메뉴얼 속 수도코드를 참고하여 구현함
    4. 구현은 다양한 방식으로 이뤄질 수 있음
    5. AES.h에 정의된 AES128(...) 함수만을 이용해서 구현해야 함
    6. XTS_AES128(...) 함수의 호출과 리턴이 여러번 반복되더라도 메모리 누수가 생기지 않게 함

 *  ============================================================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include "XTS_AES.h"
#include "AES128.h"

/*********************************************** { 구현 13 시작 } ********************************************/
#define KEY_SIZE 16
#define BLOCK_SIZE 16
extern uint8_t iv[];
uint8_t iv2[BLOCK_SIZE];

// Additional Generator function in GF(2^128) to make tweakable variable.
void GF_Mutiplication_xts(uint8_t *T){

    uint32_t x;
    uint8_t t, tt;
    
    for (x = t = 0;x < BLOCK_SIZE;x ++) {
        tt = *(T + x) >> 7;
        *(T + x) = ((*(T + x) << 1) | t) & 0xFF;
        t = tt;
    }
    if (tt) {
        *(T) ^= 0x87;
    } 
}
// Generator function in GF(2^128).
/*********************************************** { 구현 13 종료 } ********************************************/


/*  <128비트 XTS_AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  plain   평문 바이트 배열
 *  cipher  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘김
 *  size    평문 크기 (바이트 단위)
 *  key     256비트 암호키 (32바이트). 상위 16바이트는 key1, 하위 16바이트는 key2
 *
 *  [DEC 모드]
 *  plain   결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘김
 *  cipher  암호문 바이트 배열
 *  size    암호문 크기 (바이트 단위)
 *  key     256비트 암호키 (32바이트). 상위 16바이트는 key1, 하위 16바이트는 key2
 */
void XTS_AES128(BYTE *plain, BYTE *cipher, unsigned int size, BYTE* key, int mode){

	/*********************************************** { 구현 14 시작 } ********************************************/
	int i,j,tmp = 0;
	BYTE *T = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);
    BYTE *T2 = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);
	BYTE *PP = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);
    BYTE *CC = (BYTE *)malloc(sizeof(BYTE)*BLOCK_SIZE);

    for (i = 0;i < BLOCK_SIZE;i ++){
        *(iv2 + i) = *(iv + i);
    } // copy initial vector to use ENC / DEC.

	AES128(iv2,T,key + KEY_SIZE,ENC);
	// create initial T with iv. ( ∂(0) == E(key2)(iv,T) )
    
    if(mode == ENC){

    	for (i = 0;i < size/BLOCK_SIZE;i ++){

    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(PP + j) = plain[ i*BLOCK_SIZE + j ] ^ *(T + j);
    		}// create PP blocks.
    		AES128(PP,CC,key,ENC);
    		// create CC blocks.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			cipher[ i*BLOCK_SIZE + j ] = *(CC + j) ^ *(T + j);
    		}// create ciper blocks.
    		GF_Mutiplication_xts(T);
    		// create tweakable block.
    	}// when plain text is 16 multiples, it's over.

    	if (size%BLOCK_SIZE != 0){
    		// cipertext stealing.

    		for (j = 0;j < (size%BLOCK_SIZE);j ++){
    			cipher[ i*BLOCK_SIZE + j ] = cipher[ (i-1)*16 + j ];
    			*(PP + j) = *(T + j) ^ plain[ i*BLOCK_SIZE + j ];
    		}// shift and XOR.
    		for (j = size%BLOCK_SIZE;j < BLOCK_SIZE;j ++){
    			*(PP + j) = *(T + j) ^ cipher[ (i-1)*BLOCK_SIZE + j ];
    		}// create Additional PP blocks.
    		AES128(PP,CC,key,ENC);
    		// create Additional CC blocks.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			cipher[ (i-1)*BLOCK_SIZE + j ] = *(T + j) ^ *(CC + j);
    		}// create Additional ciper blocks.

    	}// when plain text length is not 16 multiples, it's done.
    	
    }else if(mode == DEC){

    	int check = (size%BLOCK_SIZE==0) ? 0 : 1; 
    	// judge variable that size%BLOCK_SIZE is 0 or is not 0.
    	// check == 0 is size%BLOCK_SIZE == 0.
    	// check == 1 is size%BLOCK_SIZE != 0.
    	for (i = 0;i < size/BLOCK_SIZE;i ++){

    		if (i == size/BLOCK_SIZE - 1 && check) {
                tmp = size/BLOCK_SIZE - 1;
                break;
            }
    	    // when ciper text length is not 16 multiples.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(CC + j) = cipher[ i*BLOCK_SIZE + j ] ^ *(T + j);
    		}// create PP blocks.
			AES128(PP,CC,key,DEC);
			// create CC blocks.
			for (j = 0;j < BLOCK_SIZE;j ++){
				plain[ i*BLOCK_SIZE + j ] = *(PP + j) ^ *(T + j);
			}// create plain blocks.
			GF_Mutiplication_xts(T);
    		// create tweakable block.
    	}

    	if (check) {
            // when ciper text length is not 16 multiples.
    		// cipertext stealing.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(T2 + j) = *(T + j);
    		}// copy tweakable block to tmp array.
    		GF_Mutiplication_xts(T);
    		// create tweakable block.
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			*(CC + j) = *(T + j) ^ cipher[ tmp*BLOCK_SIZE + j ];
    		}// create Additional ciper blocks.
    		AES128(PP,CC,key,DEC);
    		// create CC blocks.
    		for (j = 0;j < size%BLOCK_SIZE;j ++){
    			plain[ (tmp + 1)*BLOCK_SIZE + j ] = *(T + j) ^ *(PP + j);
    			*(CC + j) = *(T2 + j) ^ cipher[ (tmp + 1)*BLOCK_SIZE + j ];
    		}// shift and XOR.
    		for (j = size%BLOCK_SIZE;j < BLOCK_SIZE;j ++){
    			*(CC + j) = *(T2 + j) ^ *(T + j) ^ *(PP + j);
    		}// create Additional ciper blocks.
    		AES128(PP,CC,key,DEC);
    		for (j = 0;j < BLOCK_SIZE;j ++){
    			plain[ tmp*BLOCK_SIZE + j ] = *(T2 + j) ^ *(PP + j);
    		}// create Additional PP blocks.
    	}

    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
    free(T);
    free(T2);
    free(PP);
    free(CC);
	/*********************************************** { 구현 14 종료 } ********************************************/
}
