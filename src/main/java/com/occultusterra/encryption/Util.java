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

public class Util {
	
	public static void dump(String name, byte[] in) {
		int x=0, bar_length = ((64-name.length())/2);
		String bar_left, bar = "";
		for(int y=0; y<bar_length; ++y)
				bar += "-";
		bar_left = bar;
		if(bar_length%64 != 0)
			bar_left += "-";
		System.out.print("+"+bar_left+name+bar+"+\n|");
		for(int y=0; y<in.length; ++y) {
			System.out.format("%02x", in[y]); ++x;
			if(x==32) {
				System.out.print("|\n|");
				x=0;
			}
		} for(;x<32; ++x)
			System.out.print("  ");
		System.out.println("|\n+"+bar_left+name+bar+"+");
	}
	
}
