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

package com.occultusterra.bruteforce;

public class BruteForce {
	char[] map;
	int[] pos;
	
	public final String ALPHA_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	public final String alpha_map = "abcdefghijklmnopqrstuvwxyz";
	public final String num_map = "0123456789";
	public final String special_map = "~`!@#$%^&*()-_=+[]{}\\|;:'\",<.>/?";
	public final String specialcom_map = "!@#$%^&*.,+=_-?";
	
	public BruteForce(int len) throws Exception {
		setLength(len);
	}
	
	public boolean step() {
		pos[0] += 1;
		for(int x=0; x < pos.length; ++x) {
			if(pos[x] > map.length-1) {
				pos[x] = 0;
				if((x+1) > pos.length-1)
					return false;
				else
					pos[x+1] += 1;
			} else
				break;
		}
		return true;
	}
	
	public void setLength(int len) throws Exception {
		if(len > 0) {
			this.pos = new int[len];
			pos[0] -= 1;
		} else
			throw new Exception("Bad Length");
	}
	
	public void setMap(String map) throws Exception {
		if(map.length() > 0)
			this.map = map.toCharArray();
		else
			throw new Exception("Bad Map");
	}
	
	public void setMap(char[] map) throws Exception {
		if(map.length > 0)
			this.map = map;
		else
			throw new Exception("Bad Map");
	}
	
	public String getValue() {
		String value="";
		for(int p:pos) {
			value += map[p];
		}
		return value;
	}
}

