import sys

my_corpus_file = sys.argv[1]

my_temp_wordlist = []
wordlist_dict = {}
docID_list = []
my_wordlist = []
i = -1
inverted_index_list = {}

def invertedIndexer():
	global my_corpus_file
	global my_temp_wordlist
	global wordlist_dict
	global docID_list
	global i
	global my_wordlist
	global inverted_index_list

	""" Reading the corpus file """
	myfile = open(my_corpus_file)
	spaceChk = 0
	
	""" 
	Reading each line of the corpus and filtering the document id and the data whch is present below it.
	"""
	for line in myfile:
		stripedLine = line.strip()
		splitedLine = stripedLine.split(" ")
		""" 
		When # is encountered then I add tht inside the dictionary which keeps track of the document id and list of the 
		words inside that document.
		"""
		if splitedLine[0] == '#':
			docID_list.append(splitedLine[1])
			i += 1;
			wordlist_dict.update({splitedLine[1]:[]})
		else:
			doc_id = docID_list[i]
			local_temp_list = wordlist_dict[doc_id]			
			for word in splitedLine:
				local_temp_list.append(word)
				wordlist_dict.update({doc_id: local_temp_list})

	for did, wordList in wordlist_dict.items():
		for word in wordList:
			inverted_index_list.update({word:[]})

	for Doc_id, wordList in wordlist_dict.items():
		dict_for_tf = {}
		for word in wordList:
			dict_for_tf.update({word:0})

		count = 0
		
		for word in wordList:
			temp = dict_for_tf[word]
			temp += 1
			dict_for_tf.update({word:temp})

		"""
		creating the tuple of the documnt id and the term frequency inside it. then append 
		this tupple into the list of each of the word.
		"""
		for word, tf in dict_for_tf.items():
			docid_tf_tuple = (Doc_id,tf)
			temp_tuple_list = inverted_index_list[word]
			temp_tuple_list.append(docid_tf_tuple)
			inverted_index_list.update({word:temp_tuple_list})

	"""
	Display the result into the output screen as :
	
	word1 # doc_id  frequency # doc_id  frequency # doc_id  frequency # doc_id  frequency
	word2 # doc_id  frequency # doc_id  frequency # doc_id  frequency # doc_id  frequency
	word3 # doc_id  frequency # doc_id  frequency # doc_id  frequency # doc_id  frequency
	word4 # doc_id  frequency # doc_id  frequency # doc_id  frequency # doc_id  frequency
	"""
	for word, tupleList in inverted_index_list.items():
		if spaceChk == 0:
			print word,
			spaceChk+=1
		else:
			print "\n",word,
		for t in tupleList:
			print "#",t[0],t[1],

invertedIndexer()