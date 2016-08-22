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

public class TriJack implements CryptoHandler {
	SkipJack j1, j2, j3;
	
	public TriJack(byte[] key) {
		byte[] k1 = new byte[10];
		byte[] k2 = new byte[10];
		byte[] k3 = new byte[10];
		for(int x=0; x<10; ++x) {
			k1[x] = key[x];
			k2[x] = key[x+10];
			k3[x] = key[x+20];
		}
		j1 = new SkipJack(k1);
		j2 = new SkipJack(k2);
		j3 = new SkipJack(k3);
	}
	
	@Override
	public byte[] encrypt(byte[] block) {
		return j3.encrypt(j2.decrypt(j1.encrypt(block)));
	}
	
	@Override
	public byte[] decrypt(byte[] block) {
		return j1.decrypt(j2.encrypt(j3.decrypt(block)));
	}

	@Override
	public int getBlockSize() {
		return 8;
	}

	@Override
	public int getKeySize() {
		return 30;
	}

}
