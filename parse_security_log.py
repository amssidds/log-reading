import xml.etree.ElementTree as ET
import os

def parse_security_log_data(filename):
    """
    Parses a Windows Security Event Log XML file (e.g., security_1.txt)
    and prints a structured summary of relevant events.
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found in the current directory.")
        print(f"Please ensure it's in the same directory as the script, or provide the full path.")
        return

    print(f"\n--- Analyzing Security Log: {filename} ---")
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  Error parsing XML file '{filename}': {e}")
        print("  The file might not be well-formed XML, could be empty, or not an XML file.")
        return
    except Exception as e:
        print(f"  An unexpected error occurred while opening/parsing '{filename}': {e}")
        return

    # Common namespace for Windows Event Logs
    ns = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    
    events_found_count = 0
    
    # Attempt to find <Event> elements.
    # First try with the common namespace. If that fails, try without (for simpler XML structures).
    event_elements = root.findall('event:Event', ns)
    effective_ns = ns # Assume namespace is used
    if not event_elements:
        event_elements = root.findall('Event') # Try finding <Event> tags directly
        if event_elements:
            print("  Note: Processing events without explicit XML namespace.")
            effective_ns = {} # No namespace needed for child elements
        elif root.tag.endswith("Event"): # Check if the root itself is a single Event
             event_elements = [root]
             if root.find('System') is not None: # Check if children are un-namespaced
                 effective_ns = {}
             else: # Children might still use namespace even if root is a single Event with namespace
                 effective_ns = ns

    if not event_elements:
        print(f"  No <Event> elements found in '{filename}'.")
        print(f"  Root tag of the file is: <{root.tag}>.")
        print("  Please ensure this is a valid Windows Event Log XML file.")
        return

    for i, event_node in enumerate(event_elements):
        events_found_count += 1
        print(f"\n  --- Security Event #{i + 1} ---")
        
        # Helper to find child nodes with or without namespace
        def find_child(parent, tag_name):
            if not parent: return None
            node = parent.find(f'event:{tag_name}', effective_ns) if effective_ns else parent.find(tag_name)
            return node

        system_node = find_child(event_node, 'System')
        event_data_node = find_child(event_node, 'EventData')

        if system_node is None:
            print("    Skipping event: <System> block not found or namespace issue.")
            continue

        event_id_node = find_child(system_node, 'EventID')
        time_created_node = find_child(system_node, 'TimeCreated')
        computer_node = find_child(system_node, 'Computer')

        event_id = event_id_node.text if event_id_node is not None else "N/A"
        time_created = time_created_node.get('SystemTime') if time_created_node is not None else "N/A"
        computer = computer_node.text if computer_node is not None else "N/A"

        print(f"    Event ID: {event_id}")
        print(f"    Time Created: {time_created}")
        print(f"    Computer: {computer}")

        if event_data_node is None:
            print("    No <EventData> found for this event.")
            continue

        # Extract all <Data Name="...">...</Data> into a dictionary
        data_map = {}
        for data_element in (event_data_node.findall('event:Data', effective_ns) if effective_ns else event_data_node.findall('Data')):
            name = data_element.get('Name')
            value = data_element.text
            if name:
                data_map[name] = value if value is not None else ""

        # Print details based on Event ID
        if event_id == '4624':  # Successful Logon
            print("    Type: Successful Logon")
            print(f"      Target User: {data_map.get('TargetUserName', 'N/A')}@{data_map.get('TargetDomainName', 'N/A')}")
            print(f"      Logon Type: {data_map.get('LogonType', 'N/A')}")
            print(f"      Source IP: {data_map.get('IpAddress', 'N/A')}")
            print(f"      Workstation: {data_map.get('WorkstationName', 'N/A')}")
        elif event_id == '4625':  # Failed Logon
            print("    Type: Failed Logon")
            print(f"      Target User: {data_map.get('TargetUserName', 'N/A')}@{data_map.get('TargetDomainName', 'N/A')}")
            print(f"      Logon Type: {data_map.get('LogonType', 'N/A')}")
            print(f"      Source IP: {data_map.get('IpAddress', 'N/A')}")
            print(f"      Failure Reason: {data_map.get('FailureReason', 'N/A')}")
        elif event_id == '4688':  # Process Creation
            print("    Type: Process Creation")
            print(f"      Subject User: {data_map.get('SubjectUserName', 'N/A')}")
            print(f"      New Process Name: {data_map.get('NewProcessName', data_map.get('ProcessName', 'N/A'))}") # ProcessName for older logs
            print(f"      Command Line: {data_map.get('CommandLine', 'N/A')}")
            # ParentProcessName is more reliable in newer logs. ProcessId in 4688 is Creator Process ID.
            print(f"      Creator Process Name: {data_map.get('ParentProcessName', 'N/A')}") 
            if 'ProcessId' in data_map and not data_map.get('ParentProcessName'): # If ParentProcessName is missing, show Creator PID
                 print(f"      Creator Process ID: {data_map.get('ProcessId', 'N/A')}")
        elif event_id == '4672': # Special privileges assigned to new logon
            print("    Type: Special Privileges Assigned")
            print(f"      User: {data_map.get('SubjectUserName', 'N/A')}")
            print(f"      Privileges: {data_map.get('PrivilegeList', data_map.get('Privileges', 'N/A'))}")
        else:
            print(f"    Other Event Data (Event ID: {event_id}):")
            if data_map:
                for name, value in data_map.items():
                    print(f"      {name}: {value}")
            else:
                print("      No named data items found in EventData.")
    
    if events_found_count == 0:
        print(f"  No <Event> elements were successfully processed in '{filename}'.")
    print(f"--- Finished analyzing Security Log: {filename} ---")

if __name__ == '__main__':
    # === CRITICAL: Change this to your actual Security log filename ===
    # For example, to analyze "security_1.txt", change the line below to:
    # target_file = "security_1.txt"
    target_file = "security.xml"  # <--- EDIT THIS LINE
    # ===================================================================
    
    # This script will now try to run with the filename you set above.
    parse_security_log_data(target_file)
