#!/usr/bin/env python

import json
import time
import sys
import datetime
import ConfigParser
import argparse

from elasticsearch import Elasticsearch, helpers
import requests


# TODO add in better error handling
# TODO switch print statements to logging

class VirusTotal(object):
    def __init__(self, cuckoo=False):
        self.cfg = self.get_config()
        self.es = self.get_es_conn()
        self.index_name = self.cfg["index_name"]
        self.api_key = self.cfg["api_key"]

        # Make sure the cuckoo_url, cuckoo_machine and Cuckoo option is turned on
        if cuckoo and self.cfg["cuckoo_url"] is not None and self.cfg["cuckoo_machine"] is not None:
            self.cuckoo = True
        else:
            self.cuckoo = False

        self.push_mappings()

    def get_es_conn(self):
        if self.cfg["es_username"] is not None and self.cfg["es_password"] is not None:
            es = Elasticsearch(
                [self.cfg["es_url"]],
                http_auth=(self.cfg["es_username"], self.cfg["es_password"]))
        else:
            es = Elasticsearch([self.cfg["es_url"]])
        return es

    @staticmethod
    def get_config(config_file="virustotal.cfg"):
        config = ConfigParser.RawConfigParser()
        config.read(config_file)
        cfg_dict = dict()

        try:
            cfg_dict["api_key"] = config.get("credentials", "vt_api_key")
            cfg_dict["index_name"] = config.get("general", "index")
            cfg_dict["es_url"] = config.get("general", "es_url")
        except ConfigParser.NoOptionError:
            print "Error parsing configuration file missing a critical section"
            sys.exit(1)

        try:
            cfg_dict["es_username"] = config.get("credentials", "es_username")
            cfg_dict["es_password"] = config.get("credentials", "es_password")
        except ConfigParser.NoOptionError:
            cfg_dict["es_username"] = None
            cfg_dict["es_password"] = None

        try:
            cfg_dict["cuckoo_username"] = config.get("credentials", "cuckoo_username")
            cfg_dict["cuckoo_password"] = config.get("credentials", "cuckoo_password")
        except ConfigParser.NoOptionError:
            cfg_dict["cuckoo_username"] = None
            cfg_dict["cuckoo_password"] = None

        try:
            cfg_dict["cuckoo_url"] = config.get("general", "cuckoo_url")
            cfg_dict["cuckoo_machine"] = config.get("general", "cuckoo_machine")  # TODO allow this to be a list of machines
        except ConfigParser.NoOptionError:
            cfg_dict["cuckoo_url"] = None
            cfg_dict["cuckoo_machine"] = None

        return cfg_dict

    def pull_notifications(self):
        try:
            r = requests.get("https://www.virustotal.com/intelligence/hunting/notifications-feed/?key={0:s}&output=json"
                             .format(self.api_key))
        except Exception as e:
            print "Error retrieving notifications from VT", e
            return []
        try:
            notifications = r.json()
        except ValueError:
            return []
        return notifications["notifications"]

    @staticmethod
    def convert_date(datestring):
        fmt = "%Y-%m-%d %H:%M:%S"
        t = datetime.datetime.strptime(datestring, fmt)
        epochms = time.mktime(t.timetuple()) * 1000
        return int(epochms)

    def delete_notifications(self, notifications):
        try:
            r = requests.post(
                url="https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key={0:s}".format(
                    self.api_key),
                data=json.dumps(notifications))
        except Exception as e:
            print "Error deleteing notifications", e

    def get_file_from_vt(self, h):
        params = {'apikey': self.api_key,
                  'hash': h}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params=params)

        if response.status_code != 200:
            print "Error retrieving the file from VT with status code %s" % response.status_code
            return None

        data = response.content
        return data

    def post_process(self, notification):
        """
        This is the function that does post processing this may get complex
        Args:
            notification:
                notification to post process
        Returns:
            unicorns and rainbows
        """
        md5 = notification["md5"]
        rulename = notification["subject"]

        if self.cuckoo:
            # submit to Cuckoo
            data = self.get_file_from_vt(md5)  # this uses the same VT API key to download *THIS USES DOWNLOADS*
            files = {'file': (rulename, data)}
            params = {"tags": rulename,
                      "options": "route=none",
                      "machine": self.cfg["cuckoo_machine"],  # this is required with the current Cuckoo 2.0 RC1 API but may change
                      "platform": "windows",
                      "priority": 2,
                      "timeout": 300,
                      "custom": rulename}
            print "Submitted notification %s with hash %s to Cuckoo" % (rulename, md5)
            cuckoo_url = "%s/tasks/create/file" % self.cfg["cuckoo_url"]
            if self.cfg["cuckoo_username"] is not None and self.cfg["cuckoo_password"] is not None:
                r = requests.post(cuckoo_url, files=files, data=params,
                                  auth=requests.auth.HTTPBasicAuth(
                                      self.cfg["cuckoo_username"],
                                      self.cfg["cuckoo_password"]))
            else:
                r = requests.post(cuckoo_url, files=files, data=params)

            try:
                task_id = r.json()["task_id"]
                print "Submitted %s to cuckoo received task id %s" % (md5, task_id)
            except Exception as e:
                print "failed to submit %s to cuckoo with exception %s" % (md5, e)

    def index_notifications(self):
        # bulk data request
        bulk = []
        notifications = self.pull_notifications()
        if len(notifications) == 0:
            print "No new notifications continuing..."
            return

        ids_to_delete = []
        # get the notifications ready for insert
        for notification in notifications:
            id = notification["id"]
            ids_to_delete.append(id)
            notification.pop("id", None)

            if "first_seen" in notification:
                notification["first_seen"] = self.convert_date(notification["first_seen"])
            if "last_seen" in notification:
                notification["last_seen"] = self.convert_date(notification["last_seen"])
            notification["date"] = self.convert_date(notification["date"])
            print notification

            # send the notification to be post processed
            # TODO make this threaded or multiprocessed
            self.post_process(notification)

            request = {
                "_index": self.index_name,
                "_type": "notification",
                "_id": id,
                "_source": notification
            }

            bulk.append(request)

        try:
            helpers.bulk(self.es, bulk)
            self.delete_notifications(ids_to_delete)
            print "Inserted %s notifications successfully" % len(bulk)
        except Exception as e:
            self.es = self.get_es_conn()
            print "Error inserting data into ES; reestablished connection %s" % e

    def push_mappings(self):
        mapping = {
            "mappings": {
                "notification": {
                    "properties": {
                        "date": {"type": "date", "doc_values": True},
                        "first_seen": {"type": "date", "doc_values": True},
                        "last_seen": {"type": "date", "doc_values": True},
                        "match": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        "md5": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        "positives": {"type": "integer", "doc_values": True},
                        "ruleset_name": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        "scans": {"type": "nested"},
                        "sha1": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        "sha256": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        "size": {"type": "integer", "doc_values": True},
                        "subject": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        "total": {"type": "integer", "doc_values": True},
                        "type": {"type": "string", "index": "not_analyzed", "doc_values": True},
                    },
                    "dynamic_templates": [
                        {"notanalyzed": {
                            "match": "*",
                            "match_mapping_type": "string",
                            "mapping": {
                                "type": "string",
                                "index": "not_analyzed",
                                "doc_values": True
                            }
                        }
                        }
                    ]
                }
            }
        }
        try:
            self.es.indices.create(index=self.index_name, body=json.dumps(mapping))
        except Exception as e:
            print "Error creating the index in elasticsearch", e
            pass

    def run(self):
        while True:
            self.index_notifications()
            print "Sleeping 5 minutes"
            time.sleep(30) # todo fix back to 5 mins


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Will pull down VirusTotal notification alerts and send them to a variety of sources")
    parser.add_argument("-c", "--cuckoo", type=bool, default=False,
                        help="If this is turned on it will attempt to submit to Cuckoo")

    args = parser.parse_args()
    if args.cuckoo:
        vt = VirusTotal(cuckoo=True)
    else:
        vt = VirusTotal()
    vt.run()
