# unprotect.it rules downloader

Written on python 3, not tested for python 2.x

## Install
```shell
git clone https://github.com/CNDspace/unprotect_it_rules_downloader.git
cd unprotect_it_rules_downloader
pip install -r requirements.txt
```

## Usage
```shell
optional arguments:
  -h, --help            show this help message and exit
  -t {sigma,yara,capa,all}, --rule_type {sigma,yara,capa,all}
                        type of rules
  -p PATH, --path PATH  path to save rules

```

Run without args will download all rules in "rules" folder