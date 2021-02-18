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

public class GOST implements CryptoHandler {
	int[] key = new int[8];
	int[][] keybox = new int [8][16];
	int[] k87 = new int[256];
	int[] k65 = new int[256];
	int[] k43 = new int[256];
	int[] k21 = new int[256];
	
	public GOST(byte[] key, byte[][] keybox) {
		setKey(key);
		setKeyBox(keybox);
	}
	
	public GOST(byte[] key) {
		setKey(key);
	}
	
	public GOST(byte[][] keybox) {
		setKeyBox(keybox);
	}
	
	public GOST() {
		
	}
	
	@Override public void setKey(byte[] key) {
		for(int x=0, y=0; x<32; x+=4, ++y)
			this.key[y] = (key[x]&0xff)|((key[x+1]&0xff)<<8)|((key[x+2]&0xff)<<16)|((key[x+3]&0xff)<<24);
	}
	
	@Override public void setBoxes(byte[][][] keybox) {
		setKeyBox(keybox[0]);
	}
	
	public void setKeyBox(byte[][] keybox) {
		for(int x=0; x<8; ++x)
			for(int y=0; y<16; ++y)
				this.keybox[x][y] = keybox[x][y]&0xff;
		keybox_init();
	}
	
	void keybox_init() {
		for(int x=0; x<256; ++x) {
			k87[x] = keybox[8][x>>>4] << 4 | keybox[7][x&15];
			k65[x] = keybox[6][x>>>4] << 4 | keybox[5][x&15];
			k43[x] = keybox[4][x>>>4] << 4 | keybox[3][x&15];
			k21[x] = keybox[2][x>>>4] << 4 | keybox[1][x&15];
		}
	}
	
	interface kewi {
		int f(int x);
	}

	@Override public byte[] encrypt(byte[] block) {
		return encdec(block);
	}

	@Override public byte[] decrypt(byte[] block) {
		return encdec(block);
	}
	
	public byte[] encdec(byte[] block) {
		int n1 = (block[0]&0xff)|((block[1]&0xff)<<8)|((block[2]&0xff)<<16)|((block[3]&0xff)<<24);
		int n2 = (block[4]&0xff)|((block[5]&0xff)<<8)|((block[6]&0xff)<<16)|((block[7]&0xff)<<24);
		kewi f = (z) -> {
				z = k87[z>>>24 &255] <<24  | k65[z>>>16 &255] <<16 | 
					k43[z>>>8  &255] <<8   | k21[z &255];
			return z<<11 | z>>21;
		};
		for(int x=0; x<4; ++x)
			for(int y=0; y<8; y+=2) {
				n2 ^= f.f(n1+key[y]);
				n1 ^= f.f(n2+key[y+1]);
			}
		block[0] = (byte) (n2&0xff);
		block[1] = (byte) ((n2>>>8)&0xff);
		block[2] = (byte) ((n2>>>16)&0xff);
		block[3] = (byte) ((n2>>>24)&0xff);
		block[4] = (byte) (n1&0xff);;
		block[5] = (byte) ((n1>>>8)&0xff);
		block[6] = (byte) ((n1>>>16)&0xff);
		block[7] = (byte) ((n1>>>24)&0xff);
		
		return block;
	}

	@Override public int getBlockSize() {
		return 8;
	}

	@Override public int getKeySize() {
		return 32;
	}

	@Override public int[] getBoxSizes() {
		int[] ret = {1  /* One Box */,
					 8  /* Rows */,
					 16 /* Columns */
		};
		return ret;
	}
}
