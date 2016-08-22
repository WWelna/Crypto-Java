/*  
  Copyright (C) 2016 William Welna (wwelna@occultusterra.com)
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

package com.occultusterra.encryption.symmetric;

public class SkipJack implements CryptoHandler {
	int[] key;
	int[] ftable = {
			0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
			0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
			0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
			0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
			0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
			0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
			0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
			0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
			0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
			0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
			0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
			0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
			0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
			0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
			0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
			0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46};
	int[][] key_lookup;
	
	public SkipJack(byte[] key) {
		this.key = new int[10];
		this.key[0] = key[0]&0xff; // Who Needs a for() loop?
		this.key[1] = key[1]&0xff;
		this.key[2] = key[2]&0xff; // hi?
		this.key[3] = key[3]&0xff;
		this.key[4] = key[4]&0xff;
		this.key[5] = key[5]&0xff;
		this.key[6] = key[6]&0xff; // UMAD?
		this.key[7] = key[7]&0xff;
		this.key[8] = key[8]&0xff;
		this.key[9] = key[9]&0xff; // MAD!
		this.key_lookup = new int[32][4];
		keyLookupGen(); // Prime Key Whitening function 'g'
	}
	
	void keyLookupGen() { // does all the shifts/multi and modulus stuff once
		for(int x=0; x<32; ++x) {
			// Can't think of any more 'efficient' way to do this currently
			key_lookup[x][0] = key[((x<<2))%10];
			key_lookup[x][1] = key[((x<<2)+1)%10];
			key_lookup[x][2] = key[((x<<2)+2)%10];
			key_lookup[x][3] = key[((x<<2)+3)%10];
		}
	}
	
	interface kewi {
		int g(int z, int w);
	}
	
	@Override
	public byte[] encrypt(byte[] block) {
		int w1=((block[0]&0xff)<<8)|(block[1]&0xff);
		int w2=((block[2]&0xff)<<8)|(block[3]&0xff);
		int w3=((block[4]&0xff)<<8)|(block[5]&0xff);
		int w4=((block[6]&0xff)<<8)|(block[7]&0xff);
		int k=0;
		
		for(int x=0; x<2; ++x) {
			int tmp;
			kewi g = (z,w) -> {
				int g2,g3,g4,g5,g6;
				
				g2=(w&0xff);
				g3=(ftable[g2^key_lookup[z][0]]^((w>>>8)));
				g4=(ftable[g3^key_lookup[z][1]]^g2);
				g5=(ftable[g4^key_lookup[z][2]]^g3);
				g6=(ftable[g5^key_lookup[z][3]]^g4);

				return (g5<<8)|(g6);
			};
			for(int y=0; y<8; ++y) {
				//System.out.format("%2d %04x%04x %04x%04x\n",k,w1,w2,w3,w4);
				tmp=w4; w4=w3; w3=w2;
				w2=g.g(k,w1); w1=w2^tmp^(k+1);
				k++;
			}
			for(int y=0; y<8; ++y) {
				//System.out.format("%2d %04x%04x %04x%04x\n",k,w1,w2,w3,w4);
				tmp=w4; w4=w3;
				w3=w1^w2^(k+1);
				w2=g.g(k,w1);
				w1=tmp;
				k++;
			}
		} //System.out.format("FIN %04x%04x %04x%04x\n",w1,w2,w3,w4);
		
		block[0]=(byte) ((w1>>>8)&0xff);
		block[1]=(byte) (w1&0xff);
		block[2]=(byte) ((w2>>>8)&0xff);
		block[3]=(byte) (w2&0xff);
		block[4]=(byte) ((w3>>>8)&0xff);
		block[5]=(byte) (w3&0xff);
		block[6]=(byte) ((w4>>>8)&0xff);
		block[7]=(byte) (w4&0xff);
		
		return block;
	}
	
	@Override
	public byte[] decrypt(byte[] block) {
		int w2=((block[0]&0xff)<<8)|(block[1]&0xff);
		int w1=((block[2]&0xff)<<8)|(block[3]&0xff);
		int w4=((block[4]&0xff)<<8)|(block[5]&0xff);
		int w3=((block[6]&0xff)<<8)|(block[7]&0xff);
		int k=31;
		
		for(int x=0; x<2; ++x) {
			int tmp;
			kewi g = (z,w) -> {
				int g2,g3,g4,g5,g6;
				
				g2=((w>>>8));
				g3=(ftable[g2^key_lookup[z][3]]^(w&0xff));
				g4=(ftable[g3^key_lookup[z][2]]^g2);
				g5=(ftable[g4^key_lookup[z][1]]^g3);
				g6=(ftable[g5^key_lookup[z][0]]^g4);

				return (g6<<8)|(g5);
			};
			for(int y=0; y<8; ++y) {
				//System.out.format("%2d %04x%04x %04x%04x\n",k,w1,w2,w3,w4);
				tmp=w4; w4=w3; w3=w2;
				w2=g.g(k,w1); w1=w2^tmp^(k+1);
				k--;
			}
			for(int y=0; y<8; ++y) {
				//System.out.format("%2d %04x%04x %04x%04x\n",k,w1,w2,w3,w4);
				tmp=w4; w4=w3;
				w3=w1^w2^(k+1);
				w2=g.g(k,w1);
				w1=tmp;
				k--;
			}
		} //System.out.format("FIN %04x%04x %04x%04x\n",w2,w1,w4,w3);
		
		block[0]=(byte) ((w2>>>8)&0xff);
		block[1]=(byte) (w2&0xff);
		block[2]=(byte) ((w1>>>8)&0xff);
		block[3]=(byte) (w1&0xff);
		block[4]=(byte) ((w4>>>8)&0xff);
		block[5]=(byte) (w4&0xff);
		block[6]=(byte) ((w3>>>8)&0xff);
		block[7]=(byte) (w3&0xff);
		
		return block;
	}

	@Override
	public int getBlockSize() {
		return 8;
	}

	@Override
	public int getKeySize() {
		return 10;
	}
}
