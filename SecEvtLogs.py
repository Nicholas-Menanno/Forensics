import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

tree = ET.parse("SecurityEvt_formatted.xml")
root = tree.getroot()

# A work in progress Windows Event parser that requires a formatted xml windows security event log thats from https://github.com/frankwxu/digital-forensics-lab/blob/main/NIST_Data_Leakage_Case/
# Iterate through all System elements
# This basic script just outputs the windows security event logs 4608, 4634, 4624, 4625, 4647, 1100. This is just a learning tool not for actual use
# EVENT 4608
for system_element in root.findall(".//System"):
    event_id_element = system_element.find("EventID")
    time_created_element = system_element.find("TimeCreated")

    # Check if EventID and TimeCreated elements exist
    if (
        event_id_element is not None
        and event_id_element.text == "4608"
        and time_created_element is not None
    ):
        event_id = event_id_element.text
        system_time = time_created_element.get("SystemTime")

        # Print the lists of EventID and TimeCreated values
        print("Windows is starting up EventIDs: {} and SystemTimes: {}".format(event_id, system_time))

# EVENT 4634
for system_element in root.findall(".//System"):
    event_id_element = system_element.find("EventID")
    time_created_element = system_element.find("TimeCreated")

    # Check if EventID and TimeCreated elements exist
    if (
        event_id_element is not None
        and event_id_element.text == "4634"
        and time_created_element is not None
    ):
        event_id = event_id_element.text
        system_time = time_created_element.get("SystemTime")

        # Print the lists of EventID and TimeCreated values
        print("An account was logged off EventIDs: {} and SystemTimes: {}".format(event_id, system_time))

# EVENT 4624
for system_element in root.findall(".//System"):
    event_id_element = system_element.find("EventID")
    time_created_element = system_element.find("TimeCreated")

    # Check if EventID and TimeCreated elements exist
    if (
        event_id_element is not None
        and event_id_element.text == "4624"
        and time_created_element is not None
    ):
        event_id = event_id_element.text
        system_time = time_created_element.get("SystemTime")

        # Print the lists of EventID and TimeCreated values
        print("An account was successfully logged on EventIDs: {} and SystemTimes: {}".format(event_id, system_time))

# EVENT 4625
for system_element in root.findall(".//System"):
    event_id_element = system_element.find("EventID")
    time_created_element = system_element.find("TimeCreated")

    # Check if EventID and TimeCreated elements exist
    if (
        event_id_element is not None
        and event_id_element.text == "4625"
        and time_created_element is not None
    ):
        event_id = event_id_element.text
        system_time = time_created_element.get("SystemTime")

        # Print the lists of EventID and TimeCreated values
        print("An account failed to log on EventIDs: {} and SystemTimes: {}".format(event_id, system_time))

# EVENT 4647
for system_element in root.findall(".//System"):
    event_id_element = system_element.find("EventID")
    time_created_element = system_element.find("TimeCreated")

    # Check if EventID and TimeCreated elements exist
    if (
        event_id_element is not None
        and event_id_element.text == "4647"
        and time_created_element is not None
    ):
        event_id = event_id_element.text
        system_time = time_created_element.get("SystemTime")

        # Print the lists of EventID and TimeCreated values
        print("User initiated logoff EventIDs: {} and SystemTimes: {}".format(event_id, system_time))
		
# EVENT 1100
for system_element in root.findall(".//System"):
    event_id_element = system_element.find("EventID")
    time_created_element = system_element.find("TimeCreated")

    # Check if EventID and TimeCreated elements exist
    if (
        event_id_element is not None
        and event_id_element.text == "1100"
        and time_created_element is not None
    ):
        event_id = event_id_element.text
        system_time = time_created_element.get("SystemTime")

        # Print the lists of EventID and TimeCreated values
        print("The event logging service has shut down EventIDs: {} and SystemTimes: {}".format(event_id, system_time))
