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

public class DataCheck {
	
	// If 95% of the array is printable ascii, 20 - 7E, it's likely good
	public static boolean ascii95_check(byte[] a) {
		int total=0, error=0, error_margin= new Double(a.length * .95).intValue();
		int stop_check = a.length - error_margin;
		for(byte b:a) {
			if((b == 0x0A || b ==0x0D) || (b>=0x20 && b<=0x7E)) total++;
			else error++;
			if(error>error_margin) return false; // Over acceptable error margin
			if(total>stop_check) return true; // We got enough
		}
		return true; // Make Happy
	}
	
	// No error margin ascii 20 - 7E check
	public static boolean ascii95_strict(byte[] a) {
		for(byte b:a)
			if((b<0x20 && b>0x7E) && (b!=0x0A || b!=0x0D)) return false;
		return true;
	}
}
