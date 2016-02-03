from collections import Counter
import os
import sys


#list which keep track of the number of words which need to be omited having freq < 5
toOmit = 0
#keeps track of rank of the words
rank = 0
#set which keeps track of the frequency of the words.
set_of_freq = set()
#dictionary which keeps track of te word and the rank of that word
rank_dict = {}
#keeps track f the total numbe of the words
total_words = 0 
#general list which has entire word list
general_file_dict = {}


def toBeOmitted():
	global toOmit
	#iterate over the entire list of the words
	for word, freq in general_file_dict.items():
		#if th frequency for the given word is less than 5 then we increment the count 
		if (freq < 5):
			toOmit+=1
	print "Total words to be omitted who have Freq less than 5: ", toOmit



def mainCalculator():

	out_file = sys.argv[1]
	my_out_file = open(out_file,'r')
	general_file_counter = Counter()
	m_file_counter = Counter()
	global total_words
	global rank
	global rank_dict
	global set_of_freq
	global general_file_dict
	#iterate over the total word list
	for word in my_out_file:
		#increment the counter of total words when we face a new word
		total_words += 1
		#increment the freqency of the word 
		general_file_counter[word.strip()] += 1
		#if word is starting with m then increment the frequency of the word in the other file 
		# which keeps track of the words which start with m
		if word[0] == 'm':
			m_file_counter[word.strip()] += 1
	#makes use of the most_common utility of counter class and generate a list which gives 25 most common words.
	general_top_25_wordlist = general_file_counter.most_common(25)
	#makes use of the most_common utility of counter class and generate a list which gives 25 most common words
	#which start with m.
	m_top_25_wordlist = m_file_counter.most_common(25)
	#length of the total general list of the words to get the total words in the list.
	total_uniq_words = len(general_file_counter)
	#merging the two dictionary and generating a single one having both the lists.
	combined_word_list = dict(general_top_25_wordlist).copy()
	combined_word_list.update(dict(m_top_25_wordlist))
	general_file_dict = dict(general_file_counter)
	for key in general_file_dict.keys():
		rank_dict.update({key:0})
	#iterating over the list of words whi have been sorted with the fequency
	for key, value in (sorted(general_file_dict.items(),key=lambda item:-item[1])):
		#increment the rank and set it to the value pair of the rank_dict dictionary.
		rank+=1
		set_of_freq.add(value)
		rank_dict.update({key:rank})
	print "Total words: " ,total_words, 
	      "\nTotal unique words: ", total_uniq_words, "\n"
	#iterate over the list and calculate the probability of the word and the desired product and display it.
	for word, freq in (sorted(combined_word_list.items(),key=lambda item:-item[1])):
		Probability_word = float(freq)/total_words
		Product = rank_dict[word] * Probability_word
		print "Word : ", word ,
		      "\nFrequency :", freq, 
		      "\nRank : ", rank_dict[word],
		      "\nProbability : ", Probability_word, 
		      "\nProduct : ", Product
		print "_________________________________"
	my_out_file.close()

mainCalculator()
toBeOmitted()