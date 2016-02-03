import sys
import math 

index_file = sys.argv[1]
query_file = sys.argv[2]
max_limit = sys.argv[3]

index_dict = {}
query_n_id_dict = {}
relative_dl = {}
dl_tracker_dict = {}
avdl = 0.00
dl_size_dict = {}

"""this variable is set to true if we want to display sorted bm25 
scores of the documents and with their rank."""
sort_BM25_score = True

N = 0 

def myBm25():
	global index_dict
	global query_n_id_dict
	global bm25_score_dict
	global dl_tracker_dict
	global avdl
	global total_dl
	global relative_dl
	global N
	indexFile = open(index_file)
	queryFile = open(query_file)
	k1 = 1.2
	b = 0.75
	k2 = 100.00
	qid = 0
	total_size = 0

	""" below for loop iterates over the index.out file and creates a
	    dictionary with key as the word and value as the list of 
	    (doc_id freq) tuple."""
	for line in indexFile:
		stripedLine = line.strip()
		splitedLine = stripedLine.split(' # ')
		for tup in splitedLine[1:]:
			striptup = tup.strip()
			splittup = striptup.split(" ")
			"""dl_size_dict is dictionary which holds the key: doc id
			   and value is the size of it."""
			dl_size_dict.update({splittup[0]:0})
			myword = splitedLine[0]
			low_word = myword.lower()
			"""index_dict is the dictionary which has key as the word 
				and value as the list of (doc_id freq) tuple."""
			index_dict.update({low_word:splitedLine[1:]})

	"""
	below for loop actually updates the doc length dictionary with the values 
	of the size field.
	"""
	for word, tupList in index_dict.items():
		for tup in tupList:
			striptup = tup.strip()
			splittup = striptup.split(" ")
			size = dl_size_dict[splittup[0]]
			size += int(splittup[1])
			dl_size_dict.update({splittup[0]:size})

	"""calculating the total size of the entire documents"""
	for did , size in dl_size_dict.items():
		total_size += size

	"""calculating the average document length"""
	avdl = total_size/float(len(dl_size_dict))
	
	"""
	this relative_dl dictionary has 
		key: the document id 'x'
		Value: (length of x)/average size of documents
	"""
	for did, dl in dl_size_dict.items():
		rel_dl = dl/float(avdl)
		relative_dl.update({did:rel_dl})

	"""
	query_n_id_dict dictionary contains the id and the query line from the 
	queries.txt file.
	"""
	for query in queryFile:
		qid+=1
		stripedLine = query.strip()
		query_n_id_dict.update({qid:query})

	"""
	Below code was part of the question 1's part 2. where in I varied the 
	k1 and b parameter to see how the bm25 score varies and along with K values
	we get.
	"""
	# Here we vary: 
	# b from 0.1 to 0.9 in increments of 0.025
	# k1 from 0.2 to 3.0 in increments of 0.2
	# K1_inc = 0.2
	# b_inc = 0.1
	# while b_inc <= 0.9 and K1_inc <= 3.0:
	# 	for qid, query in query_n_id_dict.items():
	# 		display_count = 0
	# 		stripedLine = query.strip()
	# 		query_words = stripedLine.split(" ")
	# 		BM25_score = 0
	# 		for word in query_words:
	# 			N = len(dl_size_dict)
	# 			lowercase = word.lower()
	# 			if lowercase in index_dict.keys():
	# 				n = len(index_dict[lowercase])
	# 			else:
	# 				n = 0
	# 			f = float(getwordcount(word,'3127'))
	# 			rel_dl = relative_dl['3127']
	# 			R = 0
	# 			r = 0
	# 			k = K1_inc * ((1.0-b_inc)+(b_inc*rel_dl))
	# 			numerator = (r + 0.5)/(R - r + 0.5)
	# 			denominator = (n - r + 0.5)/(N - n - R + r + 0.5)
	# 			val1 = numerator/denominator
	# 			log_val = math.log(val1)
	# 			val2_numerator = (K1_inc + 1.0)*f
	# 			val2_denominator = K1_inc + f
	# 			val2 = val2_numerator/val2_denominator
	# 			qf = float(get_qf(word,query_words))
	# 			val3_numerator = (k2 + 1.0)*qf
	# 			val3_denominator = k2 + qf
	# 			val3 = val3_numerator/val3_denominator
	# 			BM25_score += log_val*val2*val3
	# 			display_count += 1
	# 		print "K: ",k, ", DOC: 3127, b:", b_inc , "k1:", K1_inc , ",BM25 SCORE:",BM25_score
	# 		break
	# 	b_inc = b_inc + 0.025
	# 	K1_inc = K1_inc + 0.2

	"""
	below loop iterates over the entire query lists and 
	gives the top max_limit bm25 scores. (it does not sort the scores)
	"""
	if not sort_BM25_score:
		"""
		iterate over the query_n_id_dict for each query line.
		"""
		for qid, query in query_n_id_dict.items():
			display_count = 0
			stripedLine = query.strip()
			query_words = stripedLine.split(" ")
			for did,dl in dl_size_dict.items():

				"""
				this is the terminating statement, which limits
				the results as per the max_limit (100 in our case).
				"""
				condition = int(display_count) < int(max_limit)
				if condition:
					BM25_score = 0
					for word in query_words:
						N = len(dl_size_dict)
						lowercase = word.lower()
						if lowercase in index_dict.keys():
							n = len(index_dict[lowercase])
						else:
							n = 0
						f = float(getwordcount(word,did))
						rel_dl = relative_dl[did]
						R = 0
						r = 0
						k = k1 * ((1.0-b)+(b*rel_dl))
						numerator = (r + 0.5)/(R - r + 0.5)
						denominator = (n - r + 0.5)/(N - n - R + r + 0.5)
						val1 = numerator/denominator
						log_val = math.log(val1)
						val2_numerator = (k1 + 1.0)*f
						val2_denominator = k + f
						val2 = val2_numerator/val2_denominator
						qf = float(get_qf(word,query_words))
						val3_numerator = (k2 + 1.0)*qf
						val3_denominator = k2 + qf
						val3 = val3_numerator/val3_denominator
						#calculatin the score for each document for each query line.
						BM25_score += log_val*val2*val3
					display_count += 1
					print "QUERY ID: ", qid, ", DOC ID: ", did, ", BM25 SCORE: ", BM25_score
	else:
		for qid, query in query_n_id_dict.items():
			rank = 0
			bm25_score_list = []
			stripedLine = query.strip()
			query_words = stripedLine.split(" ")
			for did,dl in dl_size_dict.items():
				BM25_score = 0
				for word in query_words:
					N = len(dl_size_dict)
					lowercase = word.lower()
					if lowercase in index_dict.keys():
						n = len(index_dict[lowercase])
					else:
						n = 0
					f = float(getwordcount(word,did))
					rel_dl = relative_dl[did]
					R = 0
					r = 0
					k = k1 * ((1.0-b)+(b*rel_dl))
					numerator = (r + 0.5)/(R - r + 0.5)
					denominator = (n - r + 0.5)/(N - n - R + r + 0.5)
					val1 = numerator/denominator
					log_val = math.log(val1)
					val2_numerator = (k1 + 1.0)*f
					val2_denominator = k + f
					val2 = val2_numerator/val2_denominator
					qf = float(get_qf(word,query_words))
					val3_numerator = (k2 + 1.0)*qf
					val3_denominator = k2 + qf
					val3 = val3_numerator/val3_denominator
					BM25_score += log_val*val2*val3
				temp_list = [qid,did,BM25_score]
				bm25_score_list.append(temp_list)
			"""
			Sorting the scores calculated and displaying the top 100 docs.
			"""
			bm25_score_list.sort(key =lambda x: x[2], reverse= True)
			for tup in bm25_score_list[:int(max_limit)]:
				rank += 1
				print tup[0]," Q0 ",tup[1]," ",rank," ",tup[2]," AkshayMacBookPro "

"""
This function takes the word and query as the input and returns the frequency of the input word 
inside the query (list of query words).
"""
def get_qf(myWord,myQueryList):
	qf_tracker_dict = {}
	i = 0
	for word in myQueryList:
		qf_tracker_dict.update({word:0})
	for word in myQueryList:
		i = qf_tracker_dict[word]
		i+=1
		qf_tracker_dict.update({word:i})
	return qf_tracker_dict[myWord]

"""
This function returns the word count of the word given as the input inside the document id provided.
"""
def getwordcount(myWord, did):
	count = 0
	for word, tupList in index_dict.items():
		if myWord == word:
			for tup in tupList:
				striptup = tup.strip()
				splittup = striptup.split(" ")
				if splittup[0] == did:
					count = splittup[1]
	return count


myBm25()