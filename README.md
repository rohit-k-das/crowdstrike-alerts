Push crowdstrike detections that occured in the past `duration` seconds (default is 600 seconds or 10 minutes) as slack alerts, with a minimum level of detail.

Install requirements: `pip install -r requirements.lock`

Command to run:
```
python3 main -d 300
python3 main
```
Use the -h option to get a list of options: `python3 -B main.py --help`