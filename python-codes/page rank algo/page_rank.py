import sys 
import math

inLinkFile = sys.argv[1]
sinkNodes = set()
toNode = []
myGraph = {}
inLinksToPage_p = {}
outLinksFromPage_q = {}
d = 0.85
pageRank = {}
newPageRank = {}
no_of_iterations = 4
old_PR_Perplexity = 0
PR_Perplexity = 0
tempInLink = {}
flag = True


def getPreplexity(List_of_PR):
	"""
	Retrieves the perplexity
	Perplexity is a measurement of how well a probability 
	distribution or probability model predicts a sample. 
	It may be used to compare probability models.

	Formula:  2^{H(p)}=2^{-\sum_x p(x)\log_2 p(x)}
	"""
	perplexity = 0
	entropy = 0
	for PR in List_of_PR:
		entropy += PR*math.log(PR,2)
	entropy = (-1)*entropy
	perplexity=math.pow(2,entropy)
	return perplexity


def getSourceDestLocation(line):
	""" 
	Retrieves the source and destination pages to be inputed into the 
	myGraph dictionary
	"""
	fromNode = set()
	stripedLine = line.strip()
	splitedLine = stripedLine.split(" ")
	for node in splitedLine[1:]:
		fromNode.add(node)
	return fromNode, splitedLine[0]

def loadGraph():
	""" 
	Loads the myGraph dictionary with all the pages from the inlink file.
	and creates another ditionary which keeps track of the nodes and their outlinks.
	"""
	global flag
	global myGraph
	global sinkNodes
	global inLinksToPage_p
	global pageRank
	global d
	global no_of_iterations
	global old_PR_Perplexity
	global PR_Perplexity

	myInLinkFile = open(inLinkFile)
	for line in myInLinkFile:
		fromNode, toNode = getSourceDestLocation(line)
		myGraph.update({toNode:fromNode})

	inLinksToPage_p = myGraph
	
	myInLinkFile.close()

	N = len(inLinksToPage_p.keys())

	"""
	Updates the outlink dictionary with a set having all the pages which the key 
	of the dictionary is being pointed to.
	"""
	for key in inLinksToPage_p.keys():
		outlink = set()
		outLinksFromPage_q.update({key:outlink})
	
	"""
	loading the gdictionary having count of the outlinks
	"""
	for key in inLinksToPage_p.keys():
		for inlink in inLinksToPage_p.get(key):
			outLinksFromPage_q.get(inlink).add(key)

	"""
	Filtering all the sink nodes from the outlink dictionary.
	And removing them from the dictionary.
	"""
	for key in outLinksFromPage_q.keys():
		if len(outLinksFromPage_q.get(key)) == 0:
			sinkNodes.add(key)
			del outLinksFromPage_q[key]

	"""
	Setting the page rank of all the pages initially as 1/N.
	"""
	for page in myGraph.keys():
		pageRank.update({page:1/float(N)})

	i = 0
	j = 0

	if flag:
		PR_Perplexity = getPreplexity(pageRank.values())

	"""
	while the page rank converges for atleast 4 times. 
	"""
	while(i < no_of_iterations):

		if flag:
			print "Perplexity for Iteration ", j ," : ",PR_Perplexity
			if(abs(PR_Perplexity - old_PR_Perplexity ) < 1):
				i+=1
			else:
				i=0

		sinkPR = 0
		
		for sinkNode in sinkNodes:
			sinkPR += pageRank.get(sinkNode)

		for pageP in myGraph.keys():
			newPageRank[pageP] = (1.0-d)/float(N)
			newPageRank[pageP] += (d*sinkPR)/float(N)
			
			for pageQ in myGraph.get(pageP):
				newPageRank[pageP] += (d*pageRank.get(pageQ))/len(outLinksFromPage_q.get(pageQ))

		for p in myGraph.keys():
			pageRank[p] = newPageRank[p]

		if flag:
			old_PR_Perplexity = PR_Perplexity
			PR_Perplexity = getPreplexity(pageRank.values())
			j+=1
		else:
			i+=1

	if not flag:
		print "Page Rank After ", no_of_iterations, " Iterations"
		for p, r in pageRank.items():
			print "Page :", p , " Rank: ", r
	else:
		print "---------------------------------------------"
		print "Top 50 links based on rank: "
		print "---------------------------------------------"
		for page, rank in (sorted(pageRank.items(), key= lambda item:-item[1]))[:50]:
			print "PAGE ID: ", page, " , RANK: ",  rank

		for key in inLinksToPage_p.keys():
			tempInLink.update({key:len(inLinksToPage_p[key])})


		print "---------------------------------------------"
		print "Top 50 links based on in link count: "
		print "---------------------------------------------"
		for page, inLinkCount in (sorted(tempInLink.items(), key= lambda item:-item[1]))[:50]:
			print "PAGE ID: ", page, " , In Link Count: ",  inLinkCount

loadGraph()
