import argparse
import json
from datetime import datetime
from pprint import pprint
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import re
import requests


class ScrapWithID:
    def __init__(self, completeLink):
        self.completeLink = completeLink
        self.url = requests.get(self.completeLink)
        self.data = self.__start()

    def __left_side_page(self):
        # Get the site data
        soup = BeautifulSoup(self.url.content, 'html.parser')

        # Get the VPR Section
        vpr_info = [x.text for x in soup.find('section') if x.name == 'p']

        # Get the main class of left side of the page
        main_div = soup.find('div', class_="col-md-8")

        # Find th main sections in the main class
        sections = main_div.find_all('section')

        # Get the text of the heading, severity and VPR info
        main_info = {
            "Heading": soup.find('h1').text,
            "Severity": (soup.find('span', class_=re.compile("u-m-r-1 badge badge--"))).text,
            "VPR Info": ("".join(vpr_info))
        }

        # Extract all the info
        for x in (sections[1:]):
            heading = x.find("h3").text
            if x.find("span"):
                data = [y.text for y in x.find_all("span")]
                main_info.update({str(heading).strip(): str("".join(data)).strip()})
            elif x.find("a"):
                data = [y.attrs['href'] for y in x.find_all('a')]
                main_info.update({str(heading).strip(): data})

        # Return the data from the left side
        return {"Main Info": main_info}

    def __right_side_page(self):
        # Get the site data
        soup = BeautifulSoup(self.url.content, 'html.parser')

        # Get the main class of right side of the page
        right_main_div = soup.find('div', class_="col-md-4 plugin-single__sidebar")

        # Get the tags
        tag = right_main_div.select("div p")

        # Dictionary to be filled
        plugin_details = {}

        # Extract all the info
        for x in tag:
            data = str(x.text).split(": ")
            try:
                if plugin_details.get(str(data[0]).strip()):
                    # Get the CVSS Heading
                    cvss_base = x.previous_element.previous_element.previous_element

                    # Set the heading text to add to key name
                    if cvss_base.name == 'a':
                        keyword = cvss_base.text

                    plugin_details.update({str(data[0]).strip() + f" {keyword}": str(data[1]).strip()})

                else:
                    plugin_details.update({str(data[0]).strip(): str(data[1]).strip()})

            except IndexError:
                if x.find_previous_sibling("h4").name == "h4":
                    plugin_details.update({"Exploited With": str(x.text).strip()})

            finally:
                pass

        # Return the data from the right side
        return {"Plugin Details": plugin_details}

    def __start(self):
        # Check for the status code is not 200
        if self.url.status_code != 200:
            return {'Page Status Code': self.url.status_code,
                    'URL Submitted': self.completeLink}

        # Get the left side of the page
        left = self.__left_side_page()

        # Get the right side of the page
        right = self.__right_side_page()

        # Combine both the dictionaries into one
        res = {**left, **right}

        return res


def main():
    parser = argparse.ArgumentParser(description='GET TENABLE JSON FROM URL(s)')

    # Argument is for a multiple urls
    parser.add_argument('-u', dest='urls', nargs='+', type=str, help='URLs To Crawl', required=True)

    # Argument is used to generate a single json file for each url
    parser.add_argument('-j', dest='multipleJsonFile', action='store_true', help='Get the Combined JSON File')

    # Argument is used to generate a combined json file for all url
    parser.add_argument('-i', dest='singleJsonFile', action='store_true', help='Get the individual JSON File')

    args = parser.parse_args()

    if args.urls:
        combine = []
        for url in args.urls:
            if not url.startswith("http") or not url.startswith("https"):
                url = "https://" + url

            url_parsing = urlparse(url)
            domain = url_parsing.netloc
            path = url_parsing.path
            sp_paths = path.split('/')
            family_list = ['nessus', 'was', 'lce', 'nnm']

            if domain == "www.tenable.com":
                if sp_paths[1] == 'plugins' and sp_paths[2] in family_list:
                    data = ScrapWithID(url).__getattribute__("data")

                    if args.multipleJsonFile or args.singleJsonFile:
                        combine.append(data)

                    else:
                        print(f"Tenable Data for: {data['Main Info']['Heading']} \n")
                        pprint(data)

        if args.singleJsonFile:
            un_timestamp = datetime.timestamp(datetime.now())
            with open(f'combine-{un_timestamp}.json', 'w') as file:
                json.dump(combine, file, indent=4, sort_keys=True)

            print(f"JSON File Written: combine-{un_timestamp}.json")

        if args.multipleJsonFile:
            for data in combine:
                filename = data['Main Info']['Heading']
                if ':' in filename:
                    filename = filename.replace(':', ' -')
                with open(f'{filename}.json', 'w') as file:
                    json.dump(data, file, indent=4, sort_keys=True)

                print(f"JSON File Written: {filename}.json")


if __name__ == '__main__':
    main()
