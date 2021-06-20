import argparse
import json
from datetime import datetime
from pprint import pprint
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import re
import requests


class ScrapWithID:
    """ The function of this class is to parse the tenable nessus url and convert
    the data in the form of a JSON,
    :param 'url'

    Returns the JSON
    """

    def __init__(self, completeLink):
        self.completeLink = completeLink
        self.url = requests.get(self.completeLink)
        self.data = self.__start()

    @staticmethod
    def get_index(right_main_div):
        """Get the index for the plugin details section present"""

        counter = 0

        # Iterate through the right main div
        for plugins in right_main_div:

            # Get the plugin details heading
            plugin_details = plugins.find("h4", {'class': 'border-bottom pb-1'})

            # try, except block
            try:

                # Compare the text
                if plugin_details.text == 'Plugin Details':
                    # return the index where plugin details exists
                    return counter

            except AttributeError:
                pass

            # update the counter value
            counter += 1

    def __left_side_page(self):
        """Parse the left section of the page, which contains the main info synopsis,
        description and solution"""

        # Get the site data
        soup = BeautifulSoup(self.url.content, 'html.parser')

        # Get the main class of left side of the page
        main_div = soup.find_all('div', {'class': "col-md-8"})

        # Find th main sections in the main class
        sections = main_div[1].find_all('section')

        # Get the text of the heading, severity and VPR info
        main_info = {
            "Heading": soup.find('h2').text,
            "Severity": str((soup.find('span', class_=re.compile("badge badge-"))).text).upper(),
        }

        # Extract all the info
        for x in sections:
            heading = x.find("h4").text
            if x.find("span"):
                data = [y.text for y in x.find_all("span")]
                main_info.update({str(heading).strip(): str("".join(data)).strip()})
            elif x.find("a"):
                data = [y.attrs['href'] for y in x.find_all('a')]
                main_info.update({str(heading).strip(): data})

        # Return the data from the left side
        return {"Main Info": main_info}

    def __right_side_page(self):
        """Parse the right section of the page, which contains the plugin details exists"""

        # Get the site data
        soup = BeautifulSoup(self.url.content, 'html.parser')

        # Get the main class of right side of the page
        right_main_div = soup.find_all('div', {'class': "col-md-4"})

        # Get the index for the section that has plugin details
        index = self.get_index(right_main_div)

        # Get the tags
        tag = right_main_div[index].select("div p")

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
    parser.add_argument('-u', dest='urls', nargs='+', type=str, help='URL(s) to crawl', required=True)

    # Argument is used to generate a single json file for each url
    parser.add_argument('-i', dest='multipleJsonFile', action='store_true',
                        help='Get the individual JSON file for all URL(s)')

    # Argument is used to generate a combined json file for all url
    parser.add_argument('-c', dest='singleJsonFile', action='store_true',
                        help='Get the combined JSON file for all URL(s)')

    args = parser.parse_args()

    if args.urls:
        combine = []
        for url in args.urls:
            if not url.startswith("http") and not url.startswith("https"):
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
