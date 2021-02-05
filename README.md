# Tenable Plugin Page Crawler
The flask project as well as the CLI support has been given to input a URL
of the tenable plugins page and generate the JSON file of the page.

What does the flask project do?
- Generate the JSON file
- Download button to download the page
- Supports single URL at a time
  
What does the CLI program do?
- Generate the JSON file
- Supports multiple URLs at a time
- Download a combined JSON file or individual page JSON file

### Requirements
> Python3.7
> 
> pip install -r requirements.txt

### Usage For Flask
You can change the default `host` and `port` in the `config.ini` file
```
python invoker.py
```

Tenable Plugin URL and Example URL To Submit
> https://www.tenable.com/plugins/
> 
> https://www.tenable.com/plugins/nessus/126261

### Usage For CLI
File in the `scripts` folder
```
tenableScraper.py [-h] -u URLS [URLS ...] [-j] [-i]

GET TENABLE JSON FROM URL(s)

optional arguments:
  -h, --help          show this help message and exit
  -u URLS [URLS ...]  URLs To Crawl
  -j                  Get the Combined JSON File
  -i                  Get the individual JSON File
```

### Contribution

Any kind of contributions are welcome.

1. Fork the Project
2. Commit your Changes
3. Open a Pull Request

