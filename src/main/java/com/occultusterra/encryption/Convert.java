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

package com.occultusterra.encryption;

public class Convert {
	// Writes a Big-Endian number as a Big Endian 4-byte array
	public static byte[] short2byte_be(short s) {
		byte[] r = new byte[2];
		r[0] = (byte) ((s>>>8)&0xff);
		r[1] = (byte) (s&0xff);
		return r;
	}
	
	public static byte[] int2byte_be(int i) {
		byte[] r = new byte[4];
		r[0] = (byte) ((i>>>24)&0xff); 
		r[1] = (byte) ((i>>>16)&0xff);
		r[2] = (byte) ((i>>>8)&0xff);
		r[3] = (byte) (i&0xff);
		return r;
	}
	
	public static byte[] long2byte_be(long i) {
		byte[] r = new byte[8];
		r[0] = (byte) ((i>>>56)&0xff);
		r[1] = (byte) ((i>>>48)&0xff);
		r[2] = (byte) ((i>>>40)&0xff);
		r[3] = (byte) ((i>>>32)&0xff);
		r[4] = (byte) ((i>>>24)&0xff); 
		r[5] = (byte) ((i>>>16)&0xff);
		r[6] = (byte) ((i>>>8)&0xff);
		r[7] = (byte) (i&0xff);
		return r;
	}
	
	// Load a Big Endian 4-byte array as Big Endian number
	public static short byte2short_be(byte[] b) {
		short r=0;
		r |= (b[0]&0xff)<<8;
		r |= (b[1]&0xff);
		return r;
	}
	
	public static int byte2int_be(byte[] b) {
		int r=0;
		r |= (b[0]&0xff)<<24;
		r |= (b[1]&0xff)<<16;
		r |= (b[2]&0xff)<<8;
		r |= (b[3]&0xff);
		return r;
	}
	
	public static long byte2long_be(byte[] b) {
		long r=0;
		r |= (b[0]&0xffL)<<56;
		r |= (b[1]&0xffL)<<48;
		r |= (b[2]&0xffL)<<40;
		r |= (b[3]&0xffL)<<32;
		r |= (b[4]&0xffL)<<24;
		r |= (b[5]&0xffL)<<16;
		r |= (b[6]&0xffL)<<8;
		r |= (b[7]&0xffL);
		return r;
	}
	
	// Writes a Big-Endian number as a Little Endian 4-byte array
	public static byte[] short2byte_le(short i) {
		byte[] r = new byte[2];
		r[0] = (byte) (i&0xff);
		r[1] = (byte) ((i>>>8)&0xff);
		return r;
	}
	
	public static byte[] int2byte_le(int i) {
		byte[] r = new byte[4];
		r[0] = (byte) (i&0xff);
		r[1] = (byte) ((i>>>8)&0xff);
		r[2] = (byte) ((i>>>16)&0xff);
		r[3] = (byte) ((i>>>24)&0xff);
		return r;
	}
	
	public static byte[] long2byte_le(long i) {
		byte[] r = new byte[8];
		r[0] = (byte) (i&0xff);
		r[1] = (byte) ((i>>>8)&0xff);
		r[2] = (byte) ((i>>>16)&0xff);
		r[3] = (byte) ((i>>>24)&0xff);
		r[4] = (byte) ((i>>>32)&0xff);
		r[5] = (byte) ((i>>>40)&0xff);
		r[6] = (byte) ((i>>>48)&0xff);
		r[7] = (byte) ((i>>>56)&0xff);
		return r;
	}
	
	// Load a Little Endian 4-byte array as Big Endian number
	public static short byte2short_le(byte[] b) {
		short r=0;
		r |= (b[0]&0xff);
		r |= (b[1]&0xff)<<8;
		return r;
	}
	
	public static int byte2int_le(byte[] b) {
		int r=0;
		r |= (b[0]&0xff);
		r |= (b[1]&0xff)<<8;
		r |= (b[2]&0xff)<<16;
		r |= (b[3]&0xff)<<24;
		return r;
	}
	
	public static long byte2long_le(byte[] b) {
		long r=0;
		r |= (b[0]&0xffL);
		r |= (b[1]&0xffL)<<8;
		r |= (b[2]&0xffL)<<16;
		r |= (b[3]&0xffL)<<24;
		r |= (b[4]&0xffL)<<32;
		r |= (b[5]&0xffL)<<40;
		r |= (b[6]&0xffL)<<48;
		r |= (b[7]&0xffL)<<56;
		return r;
	}
	
	// Convert a Big Endian to Little Endian, vice versa
	public static short swap(short s) {
		return (short) ((s<<8)&0xff00 | (s>>>8)&0xff);
	}
	
	public static int swap(int i) {
		return (i<<24)&0xff000000 | (i<<8)  &0xff0000 |
			   (i>>>8)&0xff00     | (i>>>24)&0xff;
	}
	
	public static long swap(long l) {
		return (l<<56) &0xff00000000000000L | (l<<40) &0xff000000000000L |
			   (l<<24) &0xff0000000000L     | (l<<8)  &0xff00000000L |
			   (l>>>8) &0xff000000L         | (l>>>24)&0xff0000L |
			   (l>>>40)&0xff00L             | (l>>>56)&0xffL;
	}
}
