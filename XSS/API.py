import requests
from bs4 import BeautifulSoup 
from collections import deque

url = input("Enter a url: ")
response = requests.get(url)

if response.status_code == 200:
    print("Request successful")
else:
    print(f"Request failed wit status code: {response.status_code
    }")
soup = BeautifulSoup(response.content, "html.parser")
links = soup.find_all("a")
for link in links:
    href = link.get("href")
    print(href)
url_queue = deque([url])
visited = set()
while url_queue:
    current_url = url_queue.popleft()
    if current_url in visited:
        continue
    print(f"Visiting: {current_url}")
    visited.add(current_url)           

    if len(visited) >= 10:
        break
    try:
        response = requests.get(current_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            link = soup.find_all("a")

            for link in links:
                href = link.get("href")
                if href and href.startswith("http") and href not in visited:
                    url_queue.append(href)
    except:
        print(f"failed to crawl: {current_url}")
print("Crawling complete!")                       
