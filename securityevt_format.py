import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

tree = ET.parse("SecurityEvt_ns_removed.xml")
root = tree.getroot()

# Taken from https://github.com/frankwxu/digital-forensics-lab/blob/main/NIST_Data_Leakage_Case/py_version/pycode/security_evt_xml/securityevt_format.py

# Use this to clean up the xml file created from EvtxECmd for viewing in the SecEvtLogs.py script

# Convert the entire XML to a string with pretty formatting
formatted_xml_str = ET.tostring(root, encoding="utf-8", method="xml").decode("utf-8")

# Parse the formatted XML content
dom = minidom.parseString(formatted_xml_str)

# Pretty print the XML content
pretty_xml = dom.toprettyxml(indent="  ")

# Remove extra blank lines
non_empty_pretty_lines = [line for line in pretty_xml.splitlines() if line.strip()]

# Join the lines to get the final XML content
formatted_xml = "\n".join(non_empty_pretty_lines)

# Save the nicely formatted XML to a new file
with open("securityEvt_formatted.xml", "w") as file:
    file.write(formatted_xml)

print("Formatted XML saved to 'securityEvt_formatted.xml'.")
