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

public class Frequencies {
	Map<Character,Double> calculated=null;
	Map<String,Double> calculated_digraphs=null;
	Map<Character,Double> calculated_first=null;
	Map<String,Long> digraphs = new HashMap<>();
	Map<Character,Long> counted = new HashMap<>();
	Map<Character,Long> first = new HashMap<>();
	long total_counted=0, digraph_counted=0, first_counted=0;
	
	public Frequencies() {
		
	}
	
	public void addData(String stuff) {
		addData(stuff.toCharArray());
	}
	
	public void addData(char[] stuff) {
		boolean is_first = true;
		for(int x=0; x<stuff.length; ++x) {
			char c = stuff[x], next;
			if(x+1<stuff.length) next = stuff[x+1];
			else next = '#';
			if(Character.isAlphabetic(c)) {
				if(is_first) { 
					is_first = false; first_counted++; 
					if(first.containsKey(Character.toUpperCase(c)))
						first.put(Character.toUpperCase(c), first.get(Character.toUpperCase(c))+1);
					else
						first.put(Character.toUpperCase(c), (long) 1);
				}
				total_counted++;
				if(counted.containsKey(Character.toUpperCase(c)))
					counted.put(Character.toUpperCase(c), counted.get(Character.toUpperCase(c))+1);
				else
					counted.put(Character.toUpperCase(c), 1l);
				if(Character.isAlphabetic(next)) {
					StringBuilder b = new StringBuilder();
					b.append(c); b.append(next);
					String digraph = b.toString().toUpperCase();
					if(digraphs.containsKey(digraph))
						digraphs.put(digraph, digraphs.get(digraph)+1);
					else
						digraphs.put(digraph, 1l);
					digraph_counted++;
				}
			} else if(Character.isSpace(c))
				is_first = true;
		}
		
	}
	
	public final Map<Character,Double> Finalize(String stuff) {
		addData(stuff);
		return Finalize();
	}
	
	public final Map<Character,Double> Finalize(char[] stuff) {
		addData(stuff);
		return Finalize();
	}
	
	public final Map<Character,Double> Finalize() {
		if(calculated != null) return calculated;
		calculated = new HashMap<>();
		calculated.put('#', (double) total_counted);
		for(Map.Entry<Character,Long> entry : counted.entrySet())
			calculated.put(entry.getKey(), Double.longBitsToDouble(entry.getValue())/Double.longBitsToDouble(total_counted));
		return calculated;
	}
	
	public final Map<Character,Double> getFirst() {
		if(calculated_first != null) return calculated_first;
		calculated_first = new HashMap<>();
		calculated_first.put('#', (double) first_counted);
		for(Map.Entry<Character,Long> entry : first.entrySet())
			calculated_first.put(entry.getKey(), Double.longBitsToDouble(entry.getValue())/Double.longBitsToDouble(first_counted));
		return calculated_first;
	}
	
	public final Map<String,Double> getDigraphs() throws Exception {
		if(calculated == null) throw new Exception("Not Finalized()"); // Not Finalized Yet
		if(calculated_digraphs != null) return calculated_digraphs;
		calculated_digraphs = new HashMap<>();
		calculated_digraphs.put("#", (double) digraph_counted);
		for(Map.Entry<String,Long> entry : digraphs.entrySet())
			if(entry.getValue()>1)
				calculated_digraphs.put(entry.getKey(), Double.longBitsToDouble(entry.getValue())/Double.longBitsToDouble(digraph_counted));
		return calculated_digraphs;
	}
}
