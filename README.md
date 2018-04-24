# Extra Intel
Bootstrapping the heck outta threat intel since 2018.

### Why?

I wanted an easy way to analyze a lot of data and enrich it with 
threat intelligence info.

### What?
This project was originally designed to accept output from the Extrahop Record API.

It returns matching records according to a set of exclusions configured in a config.ini file.

IP addresses from these records are gathered and deduplicated. They are then sent to Alienvault OTX
to be searched as indicators of compromise.

Any matches are gathered and then sent to the IBM XForce API. Any address with a risk score of 1+ on that platform
is returned to the user.

### How?
Record formats and the time frame from which to return them can be specified when the module is called, i.e.

`python inbound.py --record_choice=http --time_choice=24`

[Python Fire](https://github.com/google/python-fire) is used to create a simple CLI for interacting with modules
inbound.py and outbound.py.

The global_module.py file contains some global configuration constants - most of which are taken from config.ini.
The sample.ini file contains a sample configuration file for this project.

### Installation

Clone this repo, `cd` into it, and run `pip install -r requirements.txt`. Or something. This is very very in development
...you've been warned.