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

public class xtea implements CryptoHandler {
	int[] key = new int[4];
	int DELTA = 0x9e3779b9;
	int cycles=32;
	
	public xtea() {
		
	}
	
	public xtea(byte[] key) {
		setKey(key);
	}
	
	public xtea(byte[] key, int cycles) {
		setKey(key);
		setCycles(cycles);
	}

	@Override public void setKey(byte[] key) {
		this.key[0] = (key[0]&0xff)|((key[1]&0xff)<<8)|((key[2]&0xff)<<16)|((key[3]&0xff)<<24);
		this.key[1] = (key[4]&0xff)|((key[5]&0xff)<<8)|((key[6]&0xff)<<16)|((key[7]&0xff)<<24);
		this.key[2] = (key[8]&0xff)|((key[9]&0xff)<<8)|((key[10]&0xff)<<16)|((key[11]&0xff)<<24);
		this.key[3] = (key[12]&0xff)|((key[13]&0xff)<<8)|((key[14]&0xff)<<16)|((key[15]&0xff)<<24);
	}
	
	public void setCycles(int c) {
		if(c>32) {
			cycles=c;
		}
	}

	@Override public byte[] encrypt(byte[] block) {
		int v0=(block[0]&0xff)|((block[1]&0xff)<<8)|((block[2]&0xff)<<16)|((block[3]&0xff)<<24);
		int v1=(block[4]&0xff)|((block[5]&0xff)<<8)|((block[6]&0xff)<<16)|((block[7]&0xff)<<24);
		int sum=0;
		for(int x=0; x<cycles; ++x) {
	        v0 += (((v1<<4)^(v1>>>5))+v1)^(sum+key[sum&3]);
	        sum += DELTA;
	        v1 += (((v0<<4)^(v0>>>5))+v0)^(sum+key[(sum>>>11)&3]);
		}
		block[0] = (byte) (v0&0xff);
		block[1] = (byte) ((v0>>>8)&0xff);
		block[2] = (byte) ((v0>>>16)&0xff);
		block[3] = (byte) ((v0>>>24)&0xff);
		block[4] = (byte) (v1&0xff);
		block[5] = (byte) ((v1>>>8)&0xff);
		block[6] = (byte) ((v1>>>16)&0xff);
		block[7] = (byte) ((v1>>>24)&0xff);
		return block;
	}

	@Override public byte[] decrypt(byte[] block) {
		int v0=(block[0]&0xff)|((block[1]&0xff)<<8)|((block[2]&0xff)<<16)|((block[3]&0xff)<<24);
		int v1=(block[4]&0xff)|((block[5]&0xff)<<8)|((block[6]&0xff)<<16)|((block[7]&0xff)<<24);
		int sum=DELTA*cycles;
		for(int x=0; x<cycles; ++x) {
	        v1 -= (((v0<<4)^(v0>>>5))+v0)^(sum+key[(sum>>>11)&3]);
	        sum -= DELTA;
	        v0 -= (((v1<<4)^(v1>>>5))+v1)^(sum+key[sum&3]);
		}
		block[0] = (byte) (v0&0xff);
		block[1] = (byte) ((v0>>>8)&0xff);
		block[2] = (byte) ((v0>>>16)&0xff);
		block[3] = (byte) ((v0>>>24)&0xff);
		block[4] = (byte) (v1&0xff);
		block[5] = (byte) ((v1>>>8)&0xff);
		block[6] = (byte) ((v1>>>16)&0xff);
		block[7] = (byte) ((v1>>>24)&0xff);
		return block;
	}

	@Override public int getBlockSize() {
		return 8;
	}

	@Override public int getKeySize() {
		return 16;
	}

	@Override public int[] getBoxSizes() {
		int[] ret = {0,0,0}; // We don't use any boxes
		return ret;
	}
	
	@Override public void setBoxes(byte[][][] keybox) {
		// newp
	}

}
