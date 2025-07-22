#!/usr/bin/env python3
import boto3
import json
import ipaddress
from datetime import datetime, timedelta
import argparse

class SecurityGroupAnalyzer:
    def __init__(self, verbose=False):
        self.ec2_client = boto3.client('ec2')
        self.logs_client = boto3.client('logs')
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}
        self.verbose = verbose

    def get_security_group(self, sg_id):
        """Retrieve security group configuration"""
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
            return response['SecurityGroups'][0]
        except Exception as e:
            print(f"Error retrieving security group {sg_id}: {str(e)}")
            return None

    def get_flow_logs(self, eni_id, hours=24.0, max_flows=10000):
        """Retrieve VPC Flow Logs for the specified ENI"""
        try:
            # Find flow logs for the ENI's VPC and subnet
            eni_response = self.ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            vpc_id = eni_response['NetworkInterfaces'][0]['VpcId']
            subnet_id = eni_response['NetworkInterfaces'][0]['SubnetId']
            
            # Try multiple resource types for flow logs
            resource_ids = [eni_id, vpc_id, subnet_id]
            flow_logs = []
            
            for resource_id in resource_ids:
                flow_logs_response = self.ec2_client.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [resource_id]}]
                )
                flow_logs.extend(flow_logs_response['FlowLogs'])
            
            if not flow_logs:
                print(f"No flow logs found for ENI {eni_id}, VPC {vpc_id}, or subnet {subnet_id}")
                return []
            
            # Use the first active flow log
            active_flow_log = None
            for fl in flow_logs:
                if fl['FlowLogStatus'] == 'ACTIVE':
                    active_flow_log = fl
                    break
            
            if not active_flow_log:
                print("No active flow logs found")
                return []
            
            log_group = active_flow_log['LogGroupName']
            
            # Query flow logs in chunks to get more data
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            
            # Ensure we have at least a 1-second time range
            if (end_time - start_time).total_seconds() < 1:
                start_time = end_time - timedelta(seconds=1)
            
            # Split the time range into smaller chunks to avoid CloudWatch Logs query limits
            # CloudWatch Logs has a default limit of 10,000 results per query and often returns exactly 416 results
            # Use smaller time chunks to get more comprehensive coverage
            
            # For small time periods, use fewer chunks to avoid time range errors
            total_minutes = hours * 60
            
            if total_minutes <= 10:  # 10 minutes or less
                num_chunks = 2  # Just use 2 chunks
                chunk_hours = hours / 2
            elif total_minutes <= 30:  # 30 minutes or less
                num_chunks = 3  # Use 3 chunks
                chunk_hours = hours / 3
            elif hours <= 1:  # 1 hour or less
                num_chunks = 4  # Use 4 chunks
                chunk_hours = hours / 4
            elif hours <= 6:  # 6 hours or less
                num_chunks = 12  # Use 12 chunks
                chunk_hours = hours / 12
            else:  # More than 6 hours
                chunk_hours = 0.5  # 30-minute chunks
                num_chunks = int(hours / chunk_hours)
                
            # Ensure chunk_hours is at least 1 minute to avoid API errors
            if chunk_hours < (1/60):
                chunk_hours = 1/60  # 1 minute minimum
                
            chunk_size = min(1000, max_flows // max(1, num_chunks))  # Smaller chunk size to avoid hitting limits
            
            all_flows = []
            last_progress = -1
            print("Retrieving flow logs: ", end="", flush=True)
            for i in range(num_chunks):
                # Show progress percentage
                progress = round((i / num_chunks) * 100)
                
                # In non-verbose mode, print progress percentage at 10% intervals
                if not self.verbose and progress % 10 == 0 and progress != last_progress:
                    print(f"{progress}%", end=" ", flush=True)
                    last_progress = progress
                elif self.verbose:
                    print(f"Progress: {progress}% ({i}/{num_chunks} chunks)")
                
                # Calculate chunk boundaries, ensuring they don't overlap
                chunk_end = end_time - timedelta(hours=i * chunk_hours)
                chunk_start = chunk_end - timedelta(hours=chunk_hours)
                
                # Ensure chunk_start is not before the overall start_time
                if chunk_start < start_time:
                    chunk_start = start_time
                    
                # Ensure chunk_start is at least 1 second before chunk_end to avoid API errors
                if chunk_start >= chunk_end:
                    chunk_start = chunk_end - timedelta(seconds=1)
                
                if self.verbose:
                    print(f"Querying chunk {i+1}/{num_chunks}: {chunk_start} to {chunk_end}...")
                
                # Use a more targeted query with a limit for each chunk
                # Sort by timestamp ascending to ensure we get oldest logs first in each chunk
                # VPC Flow Logs format: version account-id interface-id srcaddr dstaddr srcport dstport...
                # Use a more precise filter with word boundaries to match the exact ENI ID
                query = f"fields @timestamp, @message | filter @message like / {eni_id} / | sort @timestamp asc"
                
                # Check if we're getting exactly the same number of results in each chunk
                # If so, we might be hitting CloudWatch Logs query limits
                max_results_per_query = chunk_size * 2  # Double the chunk size to check for limits
                
                start_query_response = self.logs_client.start_query(
                    logGroupName=log_group,
                    startTime=int(chunk_start.timestamp() * 1000),
                    endTime=int(chunk_end.timestamp() * 1000),
                    queryString=query,
                    limit=max_results_per_query
                )
                
                # Wait for query completion
                query_id = start_query_response['queryId']
                if self.verbose:
                    print(f"Waiting for chunk {i+1} query to complete...")
                while True:
                    response = self.logs_client.get_query_results(queryId=query_id)
                    if response['status'] == 'Complete':
                        if self.verbose:
                            print(f"Chunk {i+1} query complete.")
                        break
                    elif response['status'] == 'Failed':
                        print(f"Chunk {i+1} query failed.")
                        break
                    import time
                    time.sleep(1)
                    
                # Check if we might be hitting CloudWatch Logs query limits
                if len(response['results']) == 416:  # If we see the same number consistently
                    if self.verbose:
                        print(f"Note: Retrieved exactly 416 results, which may indicate a CloudWatch Logs limit")
                    
                # If we got exactly the same number of results as the chunk size,
                # we might be hitting a limit, so log a warning
                
                # Parse raw flow log messages
                chunk_flows = []
                for result in response['results']:
                    message = None
                    timestamp = None
                    for field in result:
                        if field['field'] == '@message':
                            message = field['value']
                        elif field['field'] == '@timestamp':
                            timestamp = field['value']
                    
                    if message:
                        # Parse flow log format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus
                        parts = message.strip().split()
                        if len(parts) >= 13:
                            protocol_num = int(parts[7]) if parts[7].isdigit() else 0
                            flow = {
                                '@timestamp': timestamp,
                                'version': parts[0],
                                'account_id': parts[1],
                                'interface_id': parts[2],
                                'srcaddr': parts[3],
                                'dstaddr': parts[4],
                                'srcport': parts[5],
                                'dstport': parts[6],
                                'protocol': parts[7],
                                'protocol_name': self.protocol_map.get(protocol_num, f'Protocol-{protocol_num}'),
                                'packets': parts[8],
                                'bytes': parts[9],
                                'windowstart': parts[10],
                                'windowend': parts[11],
                                'action': parts[12],
                                'flowlogstatus': parts[13] if len(parts) > 13 else 'OK'
                            }
                            
                            # We're already filtering by ENI in the query, but double-check
                            # to ensure we only process relevant flows
                            if flow['interface_id'] == eni_id:
                                chunk_flows.append(flow)
                
                if self.verbose:
                    print(f"Retrieved {len(chunk_flows)} flows from chunk {i+1} ({chunk_start} to {chunk_end})")
                all_flows.extend(chunk_flows)
                
                # Add a small delay between chunks to avoid API rate limiting
                if i < num_chunks - 1:
                    time.sleep(0.2)
                
                # Continue querying even if we've collected enough flows to ensure we cover the entire time range
                # But implement a hard cap to prevent excessive resource usage
                if len(all_flows) >= max_flows * 2:
                    if self.verbose:
                        print(f"Reached hard cap of {max_flows * 2} flows. Stopping queries.")
                    else:
                        print("(reached flow limit)")
                    break
            
            # Complete the progress indicator with a newline
            if not self.verbose:
                print("100% Complete")
            
            return all_flows
        except Exception as e:
            print(f"Error retrieving flow logs: {str(e)}")
            return []

    def is_any_any_rule(self, rule):
        """Check if a rule is an any:any rule"""
        # Check if it allows all protocols
        if rule.get('IpProtocol') != '-1':
            return False
        
        # Check if it allows all IPs
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
        
        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                return True
        
        return False

    def traffic_allowed_by_rule(self, flow, rule, is_inbound=True):
        """Check if traffic flow is allowed by a specific security group rule"""
        try:
            protocol = int(flow['protocol'])
            src_ip = flow['srcaddr']
            dst_ip = flow['dstaddr']
            src_port = int(flow['srcport'])
            dst_port = int(flow['dstport'])
            
            # Determine relevant IP and port based on direction
            if is_inbound:
                relevant_ip = src_ip
                relevant_port = dst_port
            else:
                relevant_ip = dst_ip
                relevant_port = src_port
            
            # Check protocol - convert protocol names to numbers
            rule_protocol = rule.get('IpProtocol', '-1')
            if rule_protocol != '-1':
                # Convert protocol names to numbers
                protocol_map_to_num = {'tcp': '6', 'udp': '17', 'icmp': '1'}
                rule_protocol_num = protocol_map_to_num.get(rule_protocol.lower(), rule_protocol)
                if rule_protocol_num != str(protocol):
                    return False
            
            # Check port range (skip for ICMP and other protocols that don't use ports)
            if protocol not in [1]:  # ICMP doesn't use ports
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                if not (from_port <= relevant_port <= to_port):
                    return False
            
            # Check IP ranges
            ip_allowed = False
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr and ipaddress.ip_address(relevant_ip) in ipaddress.ip_network(cidr):
                    ip_allowed = True
                    break
            
            if not ip_allowed:
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6')
                    if cidr and ipaddress.ip_address(relevant_ip) in ipaddress.ip_network(cidr):
                        ip_allowed = True
                        break
            
            return ip_allowed
        except Exception:
            return False

    def is_return_traffic(self, flow, flows, eni_ip):
        """Check if this flow is return traffic for an established session"""
        try:
            protocol = int(flow['protocol'])
            src_port = int(flow['srcport'])
            dst_port = int(flow['dstport'])
            
            # For ICMP, don't treat as return traffic - each ping is a new inbound request
            if protocol == 1:  # ICMP
                return False
            
            # Assume high destination ports (>10000) are likely return traffic or ephemeral connections
            # This catches cases where external services connect back on high ports
            if dst_port > 10000:
                return True
                
            # Common well-known ports that are typically server ports, not client return traffic
            well_known_server_ports = {22, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443}
            
            # If destination is a well-known server port, this is likely client->server traffic, not return traffic
            if dst_port in well_known_server_ports:
                return False
                
            # For all other traffic, check if there's a matching outbound flow
            # that would indicate this is return traffic
            for other_flow in flows:
                # Check for a matching outbound flow (from ENI to the source of this flow)
                if (other_flow['srcaddr'] == eni_ip and 
                    other_flow['dstaddr'] == flow['srcaddr'] and
                    other_flow['protocol'] == flow['protocol']):
                    
                    # Exact port match (typical for established connections)
                    if (other_flow['srcport'] == flow['dstport'] and
                        other_flow['dstport'] == flow['srcport']):
                        return True
                    
                    # If ENI initiated connection to this IP on any port, consider high port responses as return traffic
                    if dst_port > 1024:
                        return True
            
            # If no matching outbound flow found and not a common server port,
            # assume high source ports (>1024) connecting to non-standard destination ports
            # are likely return traffic
            if src_port > 1024 and dst_port > 1024 and dst_port not in well_known_server_ports:
                return True
                
            return False
        except Exception as e:
            if self.verbose:
                print(f"Error in return traffic detection: {str(e)}")
            return False

    def analyze_security_group(self, sg_id, eni_id, hours=24.0, max_flows=10000):
        """Main analysis function"""
        # Get actual flow logs time range
        actual_hours = hours
    
        print(f"Analyzing Security Group: {sg_id}")
        print(f"Network Interface: {eni_id}")
        # Format hours nicely (show as minutes if less than 1 hour)
        if hours < 1:
            minutes = int(hours * 60)
            print(f"Flow logs period: {minutes} minutes")
        else:
            print(f"Flow logs period: {hours} hours")
        print(f"Max flows to analyze: {max_flows}")
        print("-" * 50)
    
        # Get security group
        sg = self.get_security_group(sg_id)
        if not sg:
            return
    
        # Get flow logs
        flows = self.get_flow_logs(eni_id, hours, max_flows)
        if not flows:
            print("No flow logs available for analysis")
            return
    
        # Calculate actual time range if flows exist
        if flows:
            try:
                timestamps = []
                for flow in flows:
                    if '@timestamp' in flow:
                        try:
                            # Handle different timestamp formats
                            ts = flow.get('@timestamp', '')
                            if '.' in ts:  # Format with microseconds
                                dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
                            else:  # Format without microseconds
                                dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                            timestamps.append(dt)
                        except ValueError:
                            # Skip invalid timestamps
                            pass
                
                if timestamps:
                    min_time = min(timestamps)
                    max_time = max(timestamps)
                    actual_hours = round((max_time - min_time).total_seconds() / 3600, 1)
                    # Format time range nicely
                    if actual_hours < 1:
                        actual_minutes = int(actual_hours * 60)
                        if hours < 1:
                            max_minutes = int(hours * 60)
                            print(f"Actual time range covered: {actual_minutes} minutes (max: {max_minutes} minutes)")
                        else:
                            print(f"Actual time range covered: {actual_minutes} minutes (max: {hours} hours)")
                    else:
                        print(f"Actual time range covered: {actual_hours} hours (max: {hours} hours)")
                    print(f"Oldest log: {min_time}, Newest log: {max_time}")
            except Exception as e:
                print(f"Error calculating time range: {str(e)}")
                pass
    
        print(f"Retrieved {len(flows)} flow log entries")
            
        # Get ENI IP address for return traffic detection
        eni_response = self.ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        eni_ip = eni_response['NetworkInterfaces'][0]['PrivateIpAddress']
        
        # Identify any:any rules
        any_any_inbound = []
        any_any_outbound = []
        other_inbound = []
        other_outbound = []
        
        for rule in sg.get('IpPermissions', []):
            if self.is_any_any_rule(rule):
                any_any_inbound.append(rule)
            else:
                other_inbound.append(rule)

        
        for rule in sg.get('IpPermissionsEgress', []):
            if self.is_any_any_rule(rule):
                any_any_outbound.append(rule)
            else:
                other_outbound.append(rule)
        
        if not any_any_inbound:
            print("\nNo inbound any:any rules found in this security group")
            return

        
        # Analyze traffic that would be affected
        affected_flows = []
        still_allowed_flows = []
        total_flows = len(flows)
        inbound_flows = 0
        return_traffic_flows = 0
        
        for flow in flows:
            if flow['action'] != 'ACCEPT':
                continue
            
            # Only analyze inbound traffic (destination is the ENI)
            if flow['dstaddr'] != eni_ip:
                continue
            
            inbound_flows += 1
            
            # Skip return traffic as it's automatically allowed by stateful security groups
            if self.is_return_traffic(flow, flows, eni_ip):
                return_traffic_flows += 1
                continue
            
            # Check if inbound flow is currently allowed by inbound any:any rule
            allowed_by_any_any = False
            for rule in any_any_inbound:
                if self.traffic_allowed_by_rule(flow, rule, is_inbound=True):
                    allowed_by_any_any = True
                    break
            

            
            if allowed_by_any_any:
                # Check if it would still be allowed by other inbound rules
                allowed_by_other = False
                for rule in other_inbound:
                    if self.traffic_allowed_by_rule(flow, rule, is_inbound=True):
                        allowed_by_other = True
                        break
                
                if allowed_by_other:
                    still_allowed_flows.append(flow)
                else:
                    affected_flows.append(flow)
        

        
        print(f"\nInbound flows: {inbound_flows} (including {return_traffic_flows} return traffic flows that were excluded)")
        print(f"Note: Traffic to high ports (>10000) is automatically classified as return traffic")
        
        if affected_flows:
            # Filter out any remaining high port traffic that might have been missed
            filtered_affected = [flow for flow in affected_flows if int(flow['dstport']) <= 10000]
            
            # Count flows per unique combination
            flow_counts = {}
            for flow in filtered_affected:
                flow_key = (flow['srcaddr'], flow['protocol_name'], flow['dstport'])
                flow_counts[flow_key] = flow_counts.get(flow_key, 0) + 1
            
            # Create list of unique flows with counts
            unique_affected = []
            for flow in filtered_affected:
                flow_key = (flow['srcaddr'], flow['protocol_name'], flow['dstport'])
                if flow_key not in {f['flow_key'] for f in unique_affected}:
                    # Add count to the flow object
                    flow_with_count = flow.copy()
                    flow_with_count['count'] = flow_counts[flow_key]
                    flow_with_count['flow_key'] = flow_key
                    unique_affected.append(flow_with_count)
            
            # Sort by count (descending) to show high volume flows first
            unique_affected.sort(key=lambda x: x['count'], reverse=True)
            
            print(f"\nInbound traffic that would be BLOCKED after removing inbound any:any rules:")
            print(f"{'Source IP':<15} {'Protocol':<10} {'Dest Port':<10} {'Count':<8}")
            print("-" * 50)
            for flow in unique_affected[:20]:  # Show first 20 unique
                print(f"{flow['srcaddr']:<15} {flow['protocol_name']:<10} {flow['dstport']:<10} {flow['count']:<8}")
            
            if len(unique_affected) > 20:
                print(f"... and {len(unique_affected) - 20} more unique flows")
            # Calculate total flow count from the unique flows with counts
            total_count = sum(flow['count'] for flow in unique_affected)
            print(f"(Total {total_count} flows across {len(unique_affected)} unique combinations)")
            if len(affected_flows) != len(filtered_affected):
                print(f"(Excluded {len(affected_flows) - len(filtered_affected)} high port flows)")

        
        if still_allowed_flows:
            # Count flows per unique combination for still allowed flows
            allowed_flow_counts = {}
            for flow in still_allowed_flows:
                flow_key = (flow['srcaddr'], flow['protocol_name'], flow['dstport'])
                allowed_flow_counts[flow_key] = allowed_flow_counts.get(flow_key, 0) + 1
            
            # Create list of unique allowed flows with counts
            unique_allowed = []
            for flow in still_allowed_flows:
                flow_key = (flow['srcaddr'], flow['protocol_name'], flow['dstport'])
                if flow_key not in {f.get('flow_key') for f in unique_allowed}:
                    flow_with_count = flow.copy()
                    flow_with_count['count'] = allowed_flow_counts[flow_key]
                    flow_with_count['flow_key'] = flow_key
                    unique_allowed.append(flow_with_count)
            
            print(f"\n{len(unique_allowed)} unique traffic flows would still be allowed by other inbound rules")
            if len(still_allowed_flows) != len(unique_allowed):
                print(f"(Total {len(still_allowed_flows)} individual flows)")
        
        # Recommendation
        if not affected_flows:
            print(f"\n✅ RECOMMENDATION: Safe to remove inbound any:any rules")
            if still_allowed_flows:
                print("All current inbound traffic would still be allowed by other rules")
            else:
                print("No new inbound connections found - all traffic appears to be outbound traffic")
        else:
            print(f"\n⚠️  RECOMMENDATION: Review before removing inbound any:any rules")
            print(f"{len(affected_flows)} inbound traffic flows would be blocked")
            print("Consider adding specific inbound rules for the affected traffic first")

def main():
    parser = argparse.ArgumentParser(description='Analyze Security Group any:any rules')
    parser.add_argument('--sg-id', required=True, help='Security Group ID')
    parser.add_argument('--eni-id', required=True, help='Network Interface ID')
    parser.add_argument('--hours', type=float, default=24, help='Hours of flow logs to analyze (default: 24, can be decimal like 0.5 for 30 minutes)')
    parser.add_argument('--max-flows', type=int, default=10000, help='Maximum number of flow logs to analyze (default: 10000)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    analyzer = SecurityGroupAnalyzer(verbose=args.verbose)
    analyzer.analyze_security_group(args.sg_id, args.eni_id, args.hours, args.max_flows)

if __name__ == "__main__":
    main()