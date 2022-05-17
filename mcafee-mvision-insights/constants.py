errors = {
    401: 'Unauthorized: Client/API Key unknown',
    403: 'Unauthorized: Password mismatch',
    404: 'Method Not Allowed or Record Not Found',
    429: 'OperationLockoutError',
    500: 'Database Unavilable',
    503: 'Maximum Requests Exceeded'
}

CAMPAIGN_FIELDS = {
    "ID": "id",
    "Name": "name",
    "Threat Level ID": "threat_level_id",
    "Description": "description",
    "KB Article Link": "kb_article_link",
    "Coverage": "coverage",
    "Prevalence": "prevalence",
    "External Analysis": "external_analysis",
    "Is Coat": "is_coat",
    "Last Detected On": "last_detected_on"
}

EVENT_FIELDS = {
    "Exec UID": "exec_uid",
    "Campaign ID": "campaign_id",
    "TimeStamp": "timestamp",
    "Customer Details": "customer_details",
    "MD5": "md5",
    "SHA256": "sha256"
}

IOC_FIELDS = {
    "ID": "id",
    "Type": "type",
    "Value": "value",
    "Coverage": "coverage",
    "UID": "uid",
    "Is Coat": "is_coat",
    "Is SDB Dirty": "is-sdb-dirty"
}

GALAXIES_FIELDS = {
    "ID": "id",
    "NAME": "name",
    "Description": "description",
    "Category": "category"
}

GALAXIES_CATEGORY = {
    "MITRE Tool": "mitre-tool",
    "MITRE Attack Pattern": "mitre-attack-pattern",
    "MITRE Intrusion Set": "mitre-intrusion-set",
    "MITRE Malware": "mitre-malware",
    "MITRE Enterprise Attack Tool": "mitre-enterprise-attack-tool",
    "MITRE Enterprise Attack Malware": "mitre-enterprise-attack-malware",
    "MITRE Enterprise Attack Pattern": "mitre-enterprise-attack-attack-pattern",
    "MITRE Enterprise Attack Intrusion Set": "mitre-enterprise-attack-intrusion-set",
    "MITRE Mobile Attack Intrusion Set": "mitre-mobile-attack-intrusion-set",
    "MITRE Mobile Attack Pattern": "mitre-mobile-attack-attack-pattern",
    "MITRE Pre Attack Pattern": "mitre-pre-attack-attack-pattern",
    "MITRE Pre Attack Intrusion Set": "mitre-pre-attack-intrusion-set",
    "Ransomware MITRE Course of Action": "mitre-course-of-action",
    "Ransomware Exploit Kit": "exploit-kit",
    "Botnet": "botnet",
    "Stealer": "stealer",
    "Banker Threat Actor": "threat-actor",
    "Tool": "tool",
    "Malpedia": "malpedia",
    "RAT": "rat"
}

HISTORICAL_SEARCH_REQ_BODY = {
  "data": {
    "type": "historicalSearches",
    "attributes": {
      "query": "ProcessName != taskhost.exe",
      "startTime": "2021-09-01T09:26:22Z",
      "endTime": "2021-09-28T09:26:22Z"
    }
  }
}

REAL_TIME_SEARCH_REQ_BODY = {
  "data": {
    "type": "realTimeSearches",
    "attributes": {
      "query": "Processes name, id where Processes name equals \"csrss\" and Processes name contains \"exe\""
    }
  }
}