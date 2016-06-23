# VirusTotal Notification Puller

To run without Cuckoo submission and just indexing into ES:
```python vt_notification_pull.py```

To run with Cuckoo submission support:
```python vt_notification_pull.py -c```

## virustotal.cfg
virustotal.cfg is the configuration file and will need to be configured
at a minimum with the following options:

index: The Elasticsearch index to store virustotal notifications
vt_api_key: Your VirusTotal intelligence API key
es_url: The Elasticsearch URL such as http://localhost:9200

### Optional configuration options
es_username = Username for Elasticsearch instance if needed
es_password = Password for Elasticsearch instance if needed
cuckoo_username = Username for Cuckoo API if needed
cuckoo_password = Password for Cuckoo API if needed
cuckoo_url = URL including port for the Cuckoo API needed for Cuckoo analysis
cuckoo_machine = Cuckoo machine label to send notifications too

# Kibana

The kibana folder has dashboards, saved searches, and visualizations that
you can pull into your own Kibana instance.  A preview of one such dashboard
is below.

![Sample Dashboard](kibana/kibana.png?raw=true "Sample Dashboard")
