import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import datetime
import base64
import concurrent.futures
import time
import os
import ConfigParser


logger = logging.getLogger(__name__)

MAX_THREADS = 15  # Get max number of threads for multi-threading

crowdstrike_api = "https://api.crowdstrike.com"
Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)),'Crowdstrike_creds'))
crowdstrike_client_id = Config.get('Settings', 'Crowdstrike_Client_Id')
crowdstrike_secret = Config.get('Settings', 'Crowdstrike_Secret_Id')


class Detection:
    def __init__(self):
        self.detection_id = None
        self.device = None
        self.behavior = []
        self.severity = None
        self.seen = None
        self.created = None
        self.link = None
        self.device_id = None


# Generate session with max of 3 retries and interval of 1 second
def session_generator():
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def generate_access_token():
    logger.info('Generating Crowdstrike access token')
    access_token = None
    expiry_time = None
    headers = {'Content-Type': 'application/x-www-form-urlencoded', "accept": "application/json"}
    data = {'client_id': crowdstrike_client_id, 'client_secret': crowdstrike_secret}
    session = session_generator()
    url = "https://api.crowdstrike.com/oauth2/token"
    resp = session.post(url, headers=headers, data=data)
    if resp.ok:
        response = resp.json()
        access_token = response['access_token']
        expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=response['expires_in'])

        if "errors" in response:
            for error in response['errors']:
                logger.error("Error Code %d: %s " % (error['code'], error['message']))

    elif resp.status_code == 429:
        logger.warning('Rate Limiting encountered. Sleeping')
        response_headers = resp.headers
        seconds_to_sleep = response_headers['Retry-After']
        logger.info("Sleeping for %d seconds" % seconds_to_sleep)
        time.sleep(seconds_to_sleep)
        access_token, expiry_time = generate_access_token()
    else:
        logger.error("Unable to generate token from Query API")
        logger.error("%d:%s" % (resp.status_code, resp.text))
    return access_token, expiry_time


def revoke_access_token(access_token, expiry):
    logger.info('Revoking Crowdstrike access token')
    query_start_time = datetime.datetime.now()

    # Make the API call if token expiry time is greater than 1 minute
    if int((expiry - query_start_time).seconds) > 60:
        encoded_id_secret = base64.b64encode(bytes("%s:%s" % (crowdstrike_client_id, crowdstrike_secret), 'utf-8')).decode(encoding='UTF-8')
        headers = {'Authorization': 'Basic %s' % encoded_id_secret, 'Content-Type': 'application/x-www-form-urlencoded', "accept": "application/json"}
        data = {'token': access_token}
        session = session_generator()
        url = "https://api.crowdstrike.com/oauth2/revoke"
        resp = session.post(url, headers=headers, data=data)
        if resp.ok:
            response = resp.json()
            if "errors" in response:
                for error in response['errors']:
                    logger.error("Error Code %d: %s " % (error['code'], error['message']))

        elif resp.status_code == 429:
            logger.warning('Rate Limiting encountered. Sleeping')
            response_headers = resp.headers
            seconds_to_sleep = response_headers['Retry-After']
            logger.info("Sleeping for %d seconds" % seconds_to_sleep)
            time.sleep(seconds_to_sleep)
            revoke_access_token(access_token, expiry)
        else:
            logger.error("Unable to revoke token from Query API")
            logger.error("%d:%s" % (resp.status_code, resp.text))
    else:
        logger.info("Token has already expired. Not revoking.")


def get_detection_ids(access_token, expiry, offset=0):
    detection_ids = []
    total = 0
    logger.info('Getting detection ids')
    query_start_time = datetime.datetime.now()

    # Make the API call if token expiry time is greater than 1 minute
    if int((expiry - query_start_time).seconds) > 60:
        headers = {'Authorization': 'Bearer %s' % access_token, 'Content-Type': 'application/json',
                   "accept": "application/json"}
        params = {'filter': 'status: "new"', 'limit': 500, 'offset': offset}
        session = session_generator()
        url = "https://api.crowdstrike.com/detects/queries/detects/v1"
        resp = session.get(url, headers=headers, params=params)
        if resp.ok:
            response = resp.json()
            total = response['meta']['pagination']['total']
            detection_ids.extend(response['resources'])

            if "errors" in response:
                for error in response['errors']:
                    logger.error("Error Code %d: %s " % (error['code'], error['message']))

        elif resp.status_code == 429:
            logger.warning('Rate Limiting encountered. Sleeping')
            response_headers = resp.headers
            seconds_to_sleep = response_headers['Retry-After']
            logger.info("Sleeping for %d seconds" % seconds_to_sleep)
            time.sleep(seconds_to_sleep)
            get_detection_ids(access_token, expiry, offset)
        else:
            logger.error("Unable to get detection ids from Query API")
            logger.error("%d:%s" % (resp.status_code, resp.text))
    else:
        logger.info("Token has already expired. Not revoking.")
    return total, detection_ids


def parse_detection_results(resource):
    if resource['max_severity_displayname'] == "High" or resource['max_severity_displayname'] == 'Critical':
        detectionobj = Detection()
        detectionobj.detection_id = resource['detection_id']
        detectionobj.created = resource['created_timestamp']
        detectionobj.device = resource['device']['hostname']
        detectionobj.device_id = resource['device']['device_id']
        for each_behavior in resource['behaviors']:
            behavior = {}
            behavior['bad_behavior'] = each_behavior['cmdline']
            behavior['hash'] = each_behavior['sha256']
            behavior['parent_commandline'] = each_behavior['parent_details']['parent_cmdline']
            behavior['tactic + technique'] = each_behavior['tactic'] + "-" + each_behavior['technique']
            behavior['action_taken'] = []
            for action_taken in each_behavior['pattern_disposition_details']:
                if each_behavior['pattern_disposition_details'][action_taken]:
                    behavior['action_taken'].append(action_taken.replace('_', ' ').capitalize())
            detectionobj.behavior.append(behavior)
        detectionobj.severity = resource['max_severity_displayname']
        detectionobj.seen = resource['last_behavior']
        detectionobj.link = "https://falcon.crowdstrike.com/activity/detections/detail/%s/%s?processView=tree" % (detectionobj.device_id, detectionobj.detection_id.split(':')[2])
        return detectionobj
    return None


def get_detections(access_token, expiry, detection_ids, offset=0):
    detections = []
    headers = {'Authorization': 'Bearer %s' % access_token, 'Content-Type': 'application/json',
               "accept": "application/json"}
    data = {'ids': detection_ids}

    url = "https://api.crowdstrike.com/detects/entities/summaries/GET/v1"
    session = session_generator()
    query_start_time = datetime.datetime.now()

    # Make the API call if token expiry time is greater than 1 minute
    if int((expiry - query_start_time).seconds) > 60:
        resp = session.post(url, headers=headers, json=data)
        if resp.ok:
            response = resp.json()
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for detection in executor.map(parse_detection_results, response['resources']):
                    if detection is not None:
                        detections.append(detection)
            if "errors" in response:
                for error in response['errors']:
                    logger.error("Error Code %d: %s " % (error['code'], error['message']))

        elif resp.status_code == 429:
            logger.warning("Rate Limiting encountered. Sleeping")
            response_headers = resp.headers
            seconds_to_sleep = response_headers['Retry-After']
            logger.info("Sleeping for %d seconds" % seconds_to_sleep)
            time.sleep(seconds_to_sleep)
            get_detections(access_token, expiry, detection_ids, offset)
        else:
            logger.error("Unable to get detection info from Query API")
            logger.error("%d:%s" % (resp.status_code, resp.text))

    return detections


def fetch_detections(duration):
    access_token, expiry = generate_access_token()
    detections = []
    all_new_detection_ids = []
    if access_token is not None:
        logger.info('Fetch all new detections')
        total_detections, detection_ids = get_detection_ids(access_token, expiry)
        all_new_detection_ids.extend(detection_ids)

        # Divide the total detection into batches of 15
        if total_detections > 100:
            offsets = [i for i in range(101, total_detections, 100)]

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                for _, detection_ids in executor.map(lambda offset: get_detection_ids(access_token, expiry, offset),
                                                     offsets):
                    all_new_detection_ids.extend(detection_ids)

        logger.info('Populating detection details')
        if all_new_detection_ids:
            if len(all_new_detection_ids) > 30:
                block_of_detection_ids = [all_new_detection_ids[i:i+20] for i in range(0, len(all_new_detection_ids), 20)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    fs = [executor.submit(get_detections, access_token, expiry, detection_ids) for detection_ids in block_of_detection_ids]
                    block_of_futures = []
                    if len(fs) > 15:
                        block_of_futures = [fs[i:i + 15] for i in range(0, len(fs), 15)]
                    else:
                        block_of_futures.append(fs)
                    for futures in block_of_futures:
                        if futures:
                            for future in concurrent.futures.as_completed(futures):
                                detections.extend(future.result())
            else:
                detections.extend(get_detections(access_token, expiry, all_new_detection_ids))

        revoke_access_token(access_token, expiry)

    if detections:
        latest_detections = [detection for detection in detections if (
                    datetime.datetime.utcnow() - datetime.datetime.strptime(detection.created.split('.')[0],
                                                                            '%Y-%m-%dT%H:%M:%S')).days < 1 and (
                                         datetime.datetime.utcnow() - datetime.datetime.strptime(
                                     detection.created.split('.')[0], '%Y-%m-%dT%H:%M:%S')).seconds <= duration]
    else:
        latest_detections = []

    return latest_detections
