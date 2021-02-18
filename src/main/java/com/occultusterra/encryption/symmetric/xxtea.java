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

public class xxtea implements CryptoHandler {
	int[] key = new int[4];
	int DELTA = 0x9e3779b9;
	int blocksize=8;
	
	public xxtea() {
		
	}
	
	public xxtea(byte[] key) {
		setKey(key);
	}
	
	public xxtea(byte[] key, int b) {
		setKey(key);
		setBlockSize(b);
	}

	@Override public void setKey(byte[] key) {
		this.key[0] = (key[0]&0xff)|((key[1]&0xff)<<8)|((key[2]&0xff)<<16)|((key[3]&0xff)<<24);
		this.key[1] = (key[4]&0xff)|((key[5]&0xff)<<8)|((key[6]&0xff)<<16)|((key[7]&0xff)<<24);
		this.key[2] = (key[8]&0xff)|((key[9]&0xff)<<8)|((key[10]&0xff)<<16)|((key[11]&0xff)<<24);
		this.key[3] = (key[12]&0xff)|((key[13]&0xff)<<8)|((key[14]&0xff)<<16)|((key[15]&0xff)<<24);
	}

	@Override public byte[] encrypt(byte[] block) {
		int n=block.length/4;
		int[] v = new int[n];
		for(int x=0, i=0; x<block.length; x+=4, ++i) {
			v[i] = (block[x]&0xff)|((block[x+1]&0xff)<<8)|((block[x+2]&0xff)<<16)|((block[x+3]&0xff)<<24);
		}
		int p, y, z=v[n-1], sum=0;
		int rounds=6+52/n, e;
		do {
			sum += DELTA;
			e = (sum >>> 2) & 3;
			for(p=0; p<n-1; ++p) {
				y = v[p+1]; 
				z = v[p] += ((z>>>5^y<<2)+(y>>>3^z<<4))^((sum^y)+(key[(p&3)^e]^z));
			}
			y = v[0];
			z = v[n-1] += ((z>>>5^y<<2)+(y>>>3^z<<4))^((sum^y)+(key[(p&3)^e]^z));
		} while((--rounds)!=0);
		for(int x=0, i=0; x<block.length; x+=4, ++i) {
			block[x] = (byte) (v[i]&0xff);
			block[x+1] = (byte) ((v[i]>>>8)&0xff);
			block[x+2] = (byte) ((v[i]>>>16)&0xff);
			block[x+3] = (byte) ((v[i]>>>24)&0xff);
		}
		return block;
	}

	@Override public byte[] decrypt(byte[] block) {
		int n=block.length/4;
		int[] v = new int[n];
		for(int x=0, i=0; x<block.length; x+=4, ++i) {
			v[i] = (block[x]&0xff)|((block[x+1]&0xff)<<8)|((block[x+2]&0xff)<<16)|((block[x+3]&0xff)<<24);
		}
		int y=v[0], z;
		int p, rounds=6+52/n, e, sum=rounds*DELTA;
		do {
			e = (sum >>> 2) & 3;
			for(p=n-1; p>0; --p) {
				z = v[p-1];
				y = v[p] -= ((z>>>5^y<<2)+(y>>>3^z<<4))^((sum^y)+(key[(p&3)^e]^z));
			}
			z = v[n-1];
			y = v[0] -= ((z>>>5^y<<2)+(y>>>3^z<<4))^((sum^y)+(key[(p&3)^e]^z));
			sum -= DELTA;
		} while((--rounds)!=0);
		for(int x=0, i=0; x<block.length; x+=4, ++i) {
			block[x] = (byte) (v[i]&0xff);
			block[x+1] = (byte) ((v[i]>>>8)&0xff);
			block[x+2] = (byte) ((v[i]>>>16)&0xff);
			block[x+3] = (byte) ((v[i]>>>24)&0xff);
		}
		return block;
	}
	
	public void setBlockSize(int b) { // for modes
		if((b>8) && ((b%4)==0)) { // has to be a multiple of 32-bits of 64-bits+
			blocksize=b;
		}
	}

	@Override public int getBlockSize() {
		// xxtea has a variable block size w/ multiple of 32-bits but smallest size is 64-bits
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
		// Nothing
	}
}
