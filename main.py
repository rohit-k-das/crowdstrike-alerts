import requests
import crowdstrike_detection as crowdstrike
import logging
import click
import urllib.parse
import ConfigParser
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)-15s [%(levelname)-8s]: %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger(__name__)

Config = ConfigParser.ConfigParser()
Config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'Crowdstrike_creds'))

# Create your own slackbot
hubot_webhook_url = Config.get('Settings', 'Slackbot_Url')


# Send slack alert via hubot for each high or critical detection in crowdstrike
def send_hubot_alert_crowdstrike(detection):
    logger.info("Send hubot alert for detection %s" % detection.detection_id)

    # Emoji for slack based on action taken
    green_alerts = ['Kill process', 'Kill subprocess', 'Quarantine file', 'Kill parent', 'Process blocked',
                    'Operation blocked']
    red_alerts = ['Policy disabled']
    amber_alerts = []

    actions = []
    for behavior in detection.behavior:
        actions.extend(behavior['action_taken'])
    if actions:
        actions = list(set(actions))

    alerts = []
    if actions:
        if list(set(actions).intersection(red_alerts)):
            alerts.append(':red-alert: Allowed')
        if list(set(actions).intersection(green_alerts)):
            alerts.append(':green-alert: Blocked')
    else:
        alerts.append(':red-alert: Allowed')

    if ':green-alert: Blocked' in alerts and ':red-alert: Allowed' in alerts:
        alerts = [':amber-alert: Suspicious']

    message_to_send = ":crowd-strike: *%s* Alert: <%s|%s> ---> %s\n" % (
    detection.severity, detection.link, detection.detection_id.split(':')[2], str(alerts).strip('[').strip(']').replace("'", ""))
    message_to_send = "%sDevice: %s\n" % (message_to_send, detection.device)

    for behavior in detection.behavior:
        message_to_send = "%sBad Behavior: %s\n" % (message_to_send, behavior['bad_behavior'].replace('&', '%26amp;').replace('<', '%26lt;').replace('>', '%26gt;'))
        message_to_send = "%sHash: %s\n" % (message_to_send, behavior['hash'])
        message_to_send = "%sParent Cmd: %s\n" % (message_to_send, behavior['parent_commandline'])
        message_to_send = "%sTactic-Technique: %s\n" % (message_to_send, behavior['tactic + technique'])
        if behavior['action_taken']:
            message_to_send = "%sAction Taken: %s" % (
            message_to_send, str(behavior['action_taken']).strip('[').strip(']').replace("'", ""))
        else:
            message_to_send = "%sAction Taken: %s" % (message_to_send, 'None')
        if len(detection.behavior) > 1:
            message_to_send = "%s\n" % message_to_send

    # Whom to send the alert
    send_to = 'yourchannel or a user'
    data = {'message': message_to_send, 'users': send_to}
    data = urllib.parse.urlencode(data)

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(hubot_webhook_url, headers=headers, data=data)
    if resp.ok:
        logger.info("Sent alert to user/channel %s" % send_to)
    else:
        logger.critical("Unable to connect to hubot.")
        logger.info("Hubot Error %d:%s" % (resp.status_code, resp.text))


@click.command()
@click.option("-d", "--duration", default=600, show_default=True, nargs=1, type=int, required=False, help="Crowdstrike detections that were last seen since 'duration' seconds")
def main(duration):
    crowdstrike_detections = crowdstrike.fetch_detections(duration)
    if crowdstrike_detections:
        logger.info("Sending alerts")
        for detection in crowdstrike_detections:
            send_hubot_alert_crowdstrike(detection)


if __name__ == '__main__':
    main()
