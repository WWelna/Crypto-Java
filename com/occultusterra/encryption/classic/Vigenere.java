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

package com.occultusterra.encryption.classic;

import java.util.HashMap;
import java.util.Map;

public class Vigenere {
	char[] alph_lower  = "abcdefghijklmnopqrstuvwxyz".toCharArray();
	char[] alph_higher = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
	Map<Character,Map<Character,Character>> map_enc = new HashMap<>();
	Map<Character,Map<Character,Character>> map_dec = new HashMap<>();
	
	public Vigenere() {
		build_table();
	}
	
	void build_table() {
		for(char a='A'; a < 'Z'+1; ++a) {
			Map<Character,Character> temp_enc = new HashMap<>();
			Map<Character,Character> temp_dec = new HashMap<>();
			int x=0;
			for(char b=a; b < 'Z'+1; ++b,++x) { 
				temp_dec.put(b, alph_higher[x%26]);
				temp_enc.put(alph_higher[x%26], b);
				temp_dec.put(Character.toLowerCase(b), alph_lower[x%26]);
				temp_enc.put(alph_lower[x%26], Character.toLowerCase(b));
			}
			for(char b='A'; b < a+1; ++b,++x) {
				temp_dec.put(b, alph_higher[x%26]);
				temp_enc.put(alph_higher[x%26], b);
				temp_dec.put(Character.toLowerCase(b), alph_lower[x%26]);
				temp_enc.put(alph_lower[x%26], Character.toLowerCase(b));
			}
			map_enc.put(a, temp_enc);
			map_dec.put(a, temp_dec);
		}
	}	
	
	public String enc(String key, String txt) {
		return process(key,txt,map_enc);
	}
	
	public String dec(String key, String txt) {
		return process(key,txt,map_dec);
	}
	
	String process(String key, String txt, Map<Character,Map<Character,Character>> map) {
		StringBuilder sb = new StringBuilder();
		char[] k = key.toUpperCase().replaceAll("[^A-Z]+","").toCharArray();
		char[] pt = txt.toCharArray();
		for(int x=0, z=0; x<txt.length(); ++x) {
			Character c = map.get(k[z%k.length]).get(pt[x]);
			if(c == null)
				sb.append(pt[x]);
			else {
				sb.append(c);
				++z;
			}
		}
		return sb.toString();
	}

}
