import xml.etree.ElementTree as ET
import os

def parse_sysmon_log_data(filename):
    """
    Parses a Sysmon Event Log XML file (e.g., sysmon.txt)
    and prints a structured summary of relevant events.
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found in the current directory.")
        print(f"Please ensure it's in the same directory as the script, or provide the full path.")
        return

    print(f"\n--- Analyzing Sysmon Log: {filename} ---")
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

    # Common namespace for Windows Event Logs (Sysmon uses this too)
    ns = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    
    events_found_count = 0

    # Attempt to find <Event> elements.
    event_elements = root.findall('event:Event', ns)
    effective_ns = ns
    if not event_elements:
        event_elements = root.findall('Event')
        if event_elements:
            print("  Note: Processing events without explicit XML namespace.")
            effective_ns = {}
        elif root.tag.endswith("Event"):
             event_elements = [root]
             if root.find('System') is not None:
                 effective_ns = {}
             else:
                 effective_ns = ns

    if not event_elements:
        print(f"  No <Event> elements found in '{filename}'.")
        print(f"  Root tag of the file is: <{root.tag}>.")
        print("  Please ensure this is a valid Sysmon Event Log XML file.")
        return

    for i, event_node in enumerate(event_elements):
        events_found_count += 1
        print(f"\n  --- Sysmon Event #{i + 1} ---")

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

        print(f"    Event ID: {event_id} (Sysmon)")
        print(f"    Time Created: {time_created}")
        print(f"    Computer: {computer}")

        if event_data_node is None:
            print("    No <EventData> found for this event.")
            continue
            
        data_map = {}
        for data_element in (event_data_node.findall('event:Data', effective_ns) if effective_ns else event_data_node.findall('Data')):
            name = data_element.get('Name')
            value = data_element.text
            if name:
                data_map[name] = value if value is not None else ""

        # Print common contextual fields first
        print(f"      User: {data_map.get('User', 'N/A')}")
        print(f"      ProcessId: {data_map.get('ProcessId', 'N/A')}")
        print(f"      Image: {data_map.get('Image', 'N/A')}") # Path to executable
        if data_map.get('RuleName', '-') != '-': # Only print RuleName if it's not the default '-'
            print(f"      RuleName: {data_map.get('RuleName')}")


        if event_id == '1':  # Process Creation
            print("    Type: Process Create")
            print(f"      CommandLine: {data_map.get('CommandLine', 'N/A')}")
            print(f"      ParentProcessId: {data_map.get('ParentProcessId', 'N/A')}")
            print(f"      ParentImage: {data_map.get('ParentImage', 'N/A')}")
            print(f"      ParentCommandLine: {data_map.get('ParentCommandLine', 'N/A')}")
            if 'Hashes' in data_map: print(f"      Hashes: {data_map.get('Hashes')}")
            if 'OriginalFileName' in data_map: print(f"      OriginalFileName: {data_map.get('OriginalFileName')}")

        elif event_id == '3':  # Network Connection
            print("    Type: Network Connection")
            print(f"      Protocol: {data_map.get('Protocol', 'N/A')}")
            print(f"      SourceIp: {data_map.get('SourceIp', 'N/A')}")
            print(f"      SourcePort: {data_map.get('SourcePort', 'N/A')}")
            if 'SourceHostname' in data_map: print(f"      SourceHostname: {data_map.get('SourceHostname')}")
            print(f"      DestinationIp: {data_map.get('DestinationIp', 'N/A')}")
            print(f"      DestinationPort: {data_map.get('DestinationPort', 'N/A')}")
            if 'DestinationHostname' in data_map: print(f"      DestinationHostname: {data_map.get('DestinationHostname')}")
            print(f"      Initiated: {data_map.get('Initiated', 'N/A')}")

        elif event_id == '5':  # Process Terminated
            print("    Type: Process Terminated")
            # Key info like ProcessId and Image already printed in common fields.
            print(f"      UtcTime Terminated: {data_map.get('UtcTime', 'N/A')}")

        elif event_id == '10': # Process Access
            print("    Type: Process Access")
            print(f"      SourceImage: {data_map.get('SourceImage', 'N/A')}")
            print(f"      SourceProcessId: {data_map.get('SourceProcessId', 'N/A')}")
            print(f"      TargetImage: {data_map.get('TargetImage', 'N/A')}")
            print(f"      TargetProcessId: {data_map.get('TargetProcessId', 'N/A')}")
            print(f"      GrantedAccess: {data_map.get('GrantedAccess', 'N/A')}")
            if 'CallTrace' in data_map: print(f"      CallTrace: {data_map.get('CallTrace')}")

        elif event_id == '11': # FileCreate
            print("    Type: File Create")
            print(f"      TargetFilename: {data_map.get('TargetFilename', 'N/A')}")
            print(f"      CreationUtcTime: {data_map.get('CreationUtcTime', 'N/A')}")
            
        elif event_id == '12' or event_id == '13' or event_id == '14': # Registry Events
            event_type_map = {'12': "Registry Key/Value Create/Delete", '13': "Registry Value Set", '14': "Registry Key/Value Rename"}
            print(f"    Type: {event_type_map.get(event_id, 'Registry Event')}")
            print(f"      EventType: {data_map.get('EventType', 'N/A')}")
            print(f"      TargetObject: {data_map.get('TargetObject', 'N/A')}")
            if 'Details' in data_map: print(f"      Details: {data_map.get('Details')}")

        elif event_id == '22': # DNS Query
            print("    Type: DNS Query")
            print(f"      QueryName: {data_map.get('QueryName', 'N/A')}")
            print(f"      QueryStatus: {data_map.get('QueryStatus', 'N/A')}")
            print(f"      QueryResults: {data_map.get('QueryResults', 'N/A')}")
        else:
            print(f"    Other Sysmon Event Data (Event ID: {event_id}):")
            # Print remaining data items not covered in common or specific handlers
            printed_specific = ['User', 'ProcessId', 'Image', 'RuleName', 'CommandLine', 
                                'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'Hashes', 'OriginalFileName',
                                'Protocol', 'SourceIp', 'SourcePort', 'SourceHostname', 
                                'DestinationIp', 'DestinationPort', 'DestinationHostname', 'Initiated',
                                'UtcTime', 'SourceImage', 'TargetImage', 'TargetProcessId', 'GrantedAccess', 'CallTrace',
                                'TargetFilename', 'CreationUtcTime', 'EventType', 'TargetObject', 'Details',
                                'QueryName', 'QueryStatus', 'QueryResults']
            other_data_printed = False
            for name, value in data_map.items():
                if name not in printed_specific:
                    print(f"      {name}: {value}")
                    other_data_printed = True
            if not other_data_printed and not data_map:
                 print("      No additional named data items found in EventData.")
                 
    if events_found_count == 0:
        print(f"  No <Event> elements were successfully processed in '{filename}'.")
    print(f"--- Finished analyzing Sysmon Log: {filename} ---")

if __name__ == '__main__':
    # === CRITICAL: Change this to your actual Sysmon log filename ===
    # For example, to analyze "sysmon.txt", change the line below to:
    # target_file = "sysmon.txt"
    target_file = "sysmon.xml"  # <--- EDIT THIS LINE
    # =================================================================
    
    # This script will now try to run with the filename you set above.
    parse_sysmon_log_data(target_file)
