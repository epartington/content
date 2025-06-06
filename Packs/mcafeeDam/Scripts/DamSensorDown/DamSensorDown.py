import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    res = demisto.incidents()[0]
    subject = ""
    body = ""
    for t in demisto.incidents()[0]["labels"]:
        if t["type"] == "Email/subject":
            subject = t["value"]
        if t["type"] == "Email/text":
            body = t["value"]

    if "Sensor" not in subject:
        res = False
    if "was disconnected at" not in subject:
        res = False
    if "this is a second notification" in subject:
        res = False
    labels = []
    s = body.find("with sensor: ")
    if s > 0:
        endNamePos = min(body.index(" ", s + 13), body.index("<", s + 13))
        sensorName = body[s + 13 : endNamePos]
        labels.append({"sensorName": sensorName})

        hostLoc = body[endNamePos:].find("host: ")
        body_rest = body[endNamePos:]
        if hostLoc > 0:
            endNamePos = min(body_rest.index(" ", hostLoc + 6), body_rest.index("<", hostLoc + 6))
            host = body_rest[hostLoc + 6 : endNamePos]
            labels.append({"host": host})

            body_rest = body_rest[endNamePos:]
            ipLoc = body_rest.find("ip: ")
            if ipLoc > 0:
                endNamePos = min(body_rest.index(" ", ipLoc + 4), body_rest.index(",", ipLoc + 4))
                ip = body_rest[ipLoc + 4 : endNamePos]
                labels.append({"ip": ip})
    demisto.executeCommand("setIncident", {"addLabels": json.dumps(labels)})
    demisto.results(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
