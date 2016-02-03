from bs4 import BeautifulSoup
import re
import sys
import urllib2
import Queue
import time



#count: keeps track of count of the URL  
count = 0
#mLinkFile: text file containing list of URLs found after the final crawling process
mLinkFile = file('mLinkFile.txt', 'wt')
#visited_links: Keeps a track of URLs which have been visited while searching
#through the complete list of URLs.
visited_links = set()
#Keeps a track of the depth upto which we need to keeps iterating
depth_check = 2
#Used to keep a check on the final list of URLs which has been passed though the
#canonical filter
final_urls = set()
#this is the phrase which we need to search in all the  websites
filter_keyphrase = ''
html_data = ''
soup_data = ''
#This returns the soup data from the Beautifulsoup library
def _getSoup(html_data):
    return BeautifulSoup(html_data)

#This returns the html data for the given url
def _getHtmlData(url):
    time.sleep(1)
    req = urllib2.urlopen(url).read()
    return req

#This is the main function which will crawl through the website and retrieve the required 
#data. It takes two argument :
#feed_url: URL which is the seed or the starting page we want to crawl. 
#phrase: The string phrase which we need to search on pages.
def _mycrawler(feed_url, phrase):
    global count
    global visited_links
    depth = 1
    #to_be_crawled: This is a Queue which stores all the URLs which need to be crawled.
    to_be_crawled = Queue.Queue()
    #initialize the queue with the seed url and depth set to 1 initially
    to_be_crawled.put((feed_url,1))
    #This while loop terminates when the queue gets empty.
    while(not to_be_crawled.empty()):
        #The url which is currently in the context of crawling
        current_url, depth = to_be_crawled.get()
        #html_data: the html format data retrieved for the given 'current_url'
        html_data = _getHtmlData(current_url)
        #soup_data: the soup data retrieved for the given 'current_url's Html data
        soup_data = _getSoup(html_data)
        #cann_url: the canonical url data retrieved for the given 'current_url'
        cann_url = _retreiveCannonicalUrls(soup_data)
        #check to verify that whether the new canonical URL has been already visited or not
        if(cann_url in visited_links):
            continue
            
        #checks if the given phrase was null or no phrase was given as an input
        if(not (phrase == "")):
            #if a phrase is provided then this below checks if the current url's cannonical url 
            # has that phrase or not
            if(_notHasPhrase(html_data, phrase)):
                continue
        #After the various checks we add the canonical urls into visited list of URLs
        visited_links.add(cann_url)
        #pushing the found URL into the text file for record keeping purpose.
        mLinkFile.write(cann_url + '\n')
        print "URL visited : ", cann_url
        count = count + 1
        print "      Number : ", count
        print "       Depth : " , depth
        print "****************************"
        #checks if we have reached the threshold of the depth we have to crawl
        if(depth > depth_check):
            continue   

        #below for loop retrieves all the html 'a' tags from the soup data of the canonical url
        #and iterates over all of them and add it to the Queue for crawling further.
        for link in soup_data.find_all('a', href=True):
            link_url = link.get('href')
            #below line validates the retrieved URL for the validity filter as mentioned in the question.
            if(_validLink(link_url)):
                new_url = "http://en.wikipedia.org" + str(link_url)
                #inserting the newly found URLs into the to be crawl queue
                to_be_crawled.put((new_url,depth+1))
            
#below function checks the URL provided for the various filters
def _validLink(url):    
    if (not url.startswith('/wiki/Main_Page')
        and ":" not in url
        and url.startswith('/wiki/')):
        return True
    else:
        return False
    
#below function checks if the HTML data of the URL has the required 
#keyphrase(ignoring case sensitivity) 
def _notHasPhrase(html_data, keyphrase):
    if(keyphrase == ''):
        return True
    else:
        return (re.search(keyphrase, html_data, re.IGNORECASE) is None)
         
#this function retrieves the canonical URL for the input soup data 
#of the URL whose canonical URL we need to find out.
def _retreiveCannonicalUrls(soup):
    cann_data = soup.find("link", rel="canonical")
    cann_url = cann_data['href']
    return cann_url         
      
main_seed_url = sys.argv[1]
if(len(sys.argv) == 3):
    filter_keyphrase = sys.argv[2]
    print "phrase: ", filter_keyphrase
    _mycrawler(main_seed_url, filter_keyphrase)
else:
    filter_keyphrase = ""
    print "No phrase used "     
    _mycrawler(main_seed_url, filter_keyphrase)

print "\n TOTAL VISITED LINKS: ", len(visited_links), "\n"

if (filter_keyphrase == ""):
    print "No Keyphrase being searched."
else:
    print "Keyphrase used: ", filter_keyphrase