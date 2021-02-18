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

package com.occultusterra.encryption.modes;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import com.occultusterra.encryption.padding.PaddingHandler;
import com.occultusterra.encryption.symmetric.CryptoHandler;

public class PCBC implements ModeHandler { // Works
	CryptoHandler ch;
	PaddingHandler ph;
	int blocksize=0, keysize=0;
	byte[] IV;
	
	public PCBC() {
		
	}
	
	public PCBC(CryptoHandler ch, PaddingHandler ph) {
		setEncryption(ch);
		setPadding(ph);
	}

	@Override public void setIV(byte[] iv) throws Exception {
		for(int x=0; x<iv.length; ++x)
			IV[x] = iv[x];
	}
	
	byte[] doxor(byte[] block, byte[] plain) {
		byte[] r = new byte[block.length];
		for(int x=0; x<block.length; ++x)
			r[x] ^= block[x]^plain[x];
		return r;
	}

	@Override public byte[] encrypt(byte[] blocks) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		if(blocks.length%blocksize!=0)
			throw new Exception("Invalid Block Size");
		for(int x=0; x<blocks.length; x+=blocksize) {
			byte[] r = ch.encrypt(doxor(IV, Arrays.copyOfRange(blocks, x, x+blocksize)));
			IV=doxor(r, Arrays.copyOfRange(blocks, x, x+blocksize));
			outputStream.write(r);
		}
		return outputStream.toByteArray();
	}

	@Override public byte[] decrypt(byte[] blocks) throws Exception {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		if(blocks.length%blocksize!=0)
			throw new Exception("Invalid Block Size");
		for(int x=0; x<blocks.length; x+=blocksize) {
			byte[] r = doxor(IV, ch.decrypt(Arrays.copyOfRange(blocks, x, x+blocksize)));
			IV=doxor(r, Arrays.copyOfRange(blocks, x, x+blocksize));
			outputStream.write(r);
		}
		return outputStream.toByteArray();
	}

	@Override public byte[] encrypt_finish(byte[] blocks) throws Exception {
		return encrypt(ph.pad(blocks, blocksize));
	}

	@Override public byte[] decrypt_finish(byte[] blocks) throws Exception {
		return ph.unpad(decrypt(blocks), blocksize);
	}

	@Override public void setEncryption(CryptoHandler ch) {
		this.ch = ch;
		this.blocksize = ch.getBlockSize();
		this.keysize = ch.getKeySize();
		this.IV = new byte[this.blocksize];
	}

	@Override public void setPadding(PaddingHandler ph) {
		this.ph = ph;
	}

}