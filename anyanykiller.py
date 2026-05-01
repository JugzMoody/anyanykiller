#!/usr/bin/env python3
import boto3
import ipaddress
from datetime import datetime, timedelta
import argparse
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Default ephemeral port threshold - traffic to ports above this is considered
# likely return/ephemeral traffic. Override with --ephemeral-port-threshold.
DEFAULT_EPHEMERAL_PORT_THRESHOLD = 32768


class SecurityGroupAnalyzer:
    def __init__(self, verbose=False, ephemeral_port_threshold=DEFAULT_EPHEMERAL_PORT_THRESHOLD):
        self.ec2_client = boto3.client('ec2')
        self.logs_client = boto3.client('logs')
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}
        self.verbose = verbose
        self.ephemeral_port_threshold = ephemeral_port_threshold
        self._ip_network_cache = {}
        self._well_known_ports = {22, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443}
        # Cache stores full ENI response dict: {'PrivateIpAddress': ..., 'VpcId': ..., 'SubnetId': ...}
        self._eni_cache = {}

    def _get_eni_info(self, eni_id):
        """Retrieve and cache ENI details (IP, VPC, subnet)"""
        if eni_id not in self._eni_cache:
            eni_response = self.ec2_client.describe_network_interfaces(
                NetworkInterfaceIds=[eni_id]
            )
            eni = eni_response['NetworkInterfaces'][0]
            self._eni_cache[eni_id] = {
                'PrivateIpAddress': eni['PrivateIpAddress'],
                'VpcId': eni['VpcId'],
                'SubnetId': eni['SubnetId'],
            }
        return self._eni_cache[eni_id]

    def get_security_group(self, sg_id):
        """Retrieve security group configuration"""
        try:
            response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
            return response['SecurityGroups'][0]
        except Exception as e:
            print(f"Error retrieving security group {sg_id}: {str(e)}")
            return None

    def _get_all_flow_logs(self, resource_ids):
        """Retrieve all flow log configurations for the given resource IDs, handling pagination."""
        flow_logs = []
        for resource_id in resource_ids:
            paginator = self.ec2_client.get_paginator('describe_flow_logs')
            for page in paginator.paginate(
                Filters=[{'Name': 'resource-id', 'Values': [resource_id]}]
            ):
                flow_logs.extend(page['FlowLogs'])
        return flow_logs

    def get_flow_logs(self, eni_id, hours=24.0, max_flows=10000):
        """Retrieve VPC Flow Logs for the specified ENI"""
        all_flows = []
        try:
            # Use cached ENI info instead of a separate describe call
            eni_info = self._get_eni_info(eni_id)
            vpc_id = eni_info['VpcId']
            subnet_id = eni_info['SubnetId']

            # Try multiple resource types for flow logs (with pagination)
            resource_ids = [eni_id, vpc_id, subnet_id]
            flow_logs = self._get_all_flow_logs(resource_ids)

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
            total_minutes = hours * 60

            if total_minutes <= 10:
                num_chunks = 2
                chunk_hours = hours / 2
            elif total_minutes <= 30:
                num_chunks = 3
                chunk_hours = hours / 3
            elif hours <= 1:
                num_chunks = 4
                chunk_hours = hours / 4
            elif hours <= 6:
                num_chunks = 12
                chunk_hours = hours / 12
            else:
                chunk_hours = 0.5
                num_chunks = int(hours / chunk_hours)

            # Ensure chunk_hours is at least 1 minute to avoid API errors
            if chunk_hours < (1 / 60):
                chunk_hours = 1 / 60

            chunk_size = min(1000, max_flows // max(1, num_chunks))

            # Process chunks in parallel for better performance
            def process_chunk(chunk_info):
                i, chunk_start, chunk_end = chunk_info
                try:
                    query = f"fields @timestamp, @message | filter @message like / {eni_id} / | sort @timestamp asc"
                    max_results_per_query = chunk_size * 2

                    start_query_response = self.logs_client.start_query(
                        logGroupName=log_group,
                        startTime=int(chunk_start.timestamp() * 1000),
                        endTime=int(chunk_end.timestamp() * 1000),
                        queryString=query,
                        limit=max_results_per_query
                    )

                    query_id = start_query_response['queryId']
                    while True:
                        response = self.logs_client.get_query_results(queryId=query_id)
                        if response['status'] == 'Complete':
                            break
                        elif response['status'] == 'Failed':
                            return []
                        time.sleep(1)

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
                            parts = message.strip().split(None, 13)
                            if len(parts) >= 13:
                                protocol_num = int(parts[7]) if parts[7].isdigit() else 0
                                flow = {
                                    '@timestamp': timestamp,
                                    'version': parts[0],
                                    'account_id': parts[1],
                                    'interface_id': parts[2],
                                    'srcaddr': parts[3],
                                    'dstaddr': parts[4],
                                    'srcport': int(parts[5]) if parts[5].isdigit() else 0,
                                    'dstport': int(parts[6]) if parts[6].isdigit() else 0,
                                    'protocol': int(parts[7]) if parts[7].isdigit() else 0,
                                    'protocol_name': self.protocol_map.get(protocol_num, f'Protocol-{protocol_num}'),
                                    'packets': int(parts[8]) if parts[8].isdigit() else 0,
                                    'bytes': int(parts[9]) if parts[9].isdigit() else 0,
                                    'windowstart': parts[10],
                                    'windowend': parts[11],
                                    'action': parts[12],
                                    'flowlogstatus': parts[13] if len(parts) > 13 else 'OK'
                                }

                                if flow['interface_id'] == eni_id:
                                    chunk_flows.append(flow)

                    return chunk_flows
                except Exception as e:
                    if self.verbose:
                        print(f"Error processing chunk {i}: {e}")
                    return []

            # Prepare chunk information
            chunk_infos = []
            for i in range(num_chunks):
                chunk_end = end_time - timedelta(hours=i * chunk_hours)
                chunk_start = chunk_end - timedelta(hours=chunk_hours)

                if chunk_start < start_time:
                    chunk_start = start_time
                if chunk_start >= chunk_end:
                    chunk_start = chunk_end - timedelta(seconds=1)

                chunk_infos.append((i, chunk_start, chunk_end))

            print("Retrieving flow logs:", flush=True)

            # Use parallel processing for chunks
            # Note: process_chunk only reads self.protocol_map and self.verbose (immutable during run).
            # If caches are ever written from threads, add a threading.Lock.
            with ThreadPoolExecutor(max_workers=min(4, num_chunks)) as executor:
                future_to_chunk = {
                    executor.submit(process_chunk, chunk_info): chunk_info
                    for chunk_info in chunk_infos
                }

                completed = 0
                for future in as_completed(future_to_chunk):
                    chunk_flows = future.result()
                    all_flows.extend(chunk_flows)

                    completed += 1
                    progress = round((completed / num_chunks) * 100)
                    if not self.verbose and progress % 25 == 0:
                        print(f"  {progress}%", end="", flush=True)
                    elif self.verbose:
                        chunk_info = future_to_chunk[future]
                        print(f"Completed chunk {chunk_info[0]+1}/{num_chunks}: {len(chunk_flows)} flows")

                    # Early termination if we have enough flows
                    if len(all_flows) >= max_flows * 2:
                        if self.verbose:
                            print(f"Reached flow limit, cancelling remaining chunks")
                        for f in future_to_chunk:
                            if not f.done():
                                f.cancel()
                        break

            if not self.verbose:
                print(" Complete")

            return all_flows
        except Exception as e:
            print(f"\nError retrieving flow logs: {str(e)}")
            # Return whatever we collected so far rather than losing partial data
            if all_flows:
                print(f"Returning {len(all_flows)} partial flow log entries collected before error")
            return all_flows

    def is_any_any_rule(self, rule):
        """Check if a rule is an any:any rule"""
        if rule.get('IpProtocol') != '-1':
            return False

        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True

        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                return True

        return False

    def _check_protocol(self, flow_protocol, rule_protocol):
        """Check if flow protocol matches rule protocol"""
        if rule_protocol == '-1':
            return True
        protocol_map_to_num = {'tcp': 6, 'udp': 17, 'icmp': 1}
        rule_protocol_num = protocol_map_to_num.get(
            rule_protocol.lower(),
            int(rule_protocol) if rule_protocol.isdigit() else -1
        )
        return rule_protocol_num == flow_protocol

    def _check_port_range(self, port, rule, protocol):
        """Check if port is within rule's port range"""
        if protocol == 1:  # ICMP doesn't use ports
            return True
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        return from_port <= port <= to_port

    def _get_cached_network(self, cidr):
        """Get cached IP network object"""
        if cidr not in self._ip_network_cache:
            self._ip_network_cache[cidr] = ipaddress.ip_network(cidr)
        return self._ip_network_cache[cidr]

    def _check_ip_ranges(self, ip_addr, rule):
        """Check if IP address is allowed by rule's IP ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr and ip_obj in self._get_cached_network(cidr):
                    return True

            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr = ipv6_range.get('CidrIpv6')
                if cidr and ip_obj in self._get_cached_network(cidr):
                    return True
        except ValueError:
            return False

        return False

    def traffic_allowed_by_rule(self, flow, rule, is_inbound=True):
        """Check if traffic flow is allowed by a specific security group rule"""
        try:
            protocol = flow['protocol']
            src_ip = flow['srcaddr']
            dst_ip = flow['dstaddr']
            src_port = flow['srcport']
            dst_port = flow['dstport']

            relevant_ip = src_ip if is_inbound else dst_ip
            relevant_port = dst_port if is_inbound else src_port

            if not self._check_protocol(protocol, rule.get('IpProtocol', '-1')):
                return False

            if not self._check_port_range(relevant_port, rule, protocol):
                return False

            return self._check_ip_ranges(relevant_ip, rule)
        except (ValueError, TypeError) as e:
            if self.verbose:
                print(f"Error checking traffic rule: {str(e)}")
            return False

    def _build_flow_index(self, flows, eni_ip, direction='outbound'):
        """Build an index of flows for faster lookup, keyed by (remote_ip, protocol).

        Args:
            flows: List of flow log dicts.
            eni_ip: The ENI's private IP address.
            direction: 'outbound' indexes flows FROM eni_ip (for inbound return traffic detection).
                       'inbound' indexes flows TO eni_ip (for outbound return traffic detection).
        """
        indexed_flows = defaultdict(list)
        for flow in flows:
            if direction == 'outbound' and flow['srcaddr'] == eni_ip:
                key = (flow['dstaddr'], flow['protocol'])
                indexed_flows[key].append(flow)
            elif direction == 'inbound' and flow['dstaddr'] == eni_ip:
                key = (flow['srcaddr'], flow['protocol'])
                indexed_flows[key].append(flow)
        return indexed_flows

    def is_return_traffic(self, flow, flows, eni_ip, outbound_index=None):
        """Check if this flow is return traffic for an established session.

        Uses a conservative approach: only classifies traffic as return traffic when
        there is strong evidence of a matching outbound session (exact port-pair match).
        Traffic that cannot be confidently classified is left for rule analysis, which
        is the safer default — it may flag extra traffic for review, but won't silently
        hide legitimate inbound connections.
        """
        try:
            protocol = flow['protocol']
            src_port = flow['srcport']
            dst_port = flow['dstport']

            # ICMP: don't treat as return traffic — each ping is a distinct inbound request
            if protocol == 1:
                return False

            # If destination is a well-known server port, this is client->server traffic
            if dst_port in self._well_known_ports:
                return False

            # Look for a matching outbound flow with exact port-pair swap
            if outbound_index:
                key = (flow['srcaddr'], protocol)
                matching_flows = outbound_index.get(key, [])
            else:
                matching_flows = [
                    f for f in flows
                    if f['srcaddr'] == eni_ip
                    and f['dstaddr'] == flow['srcaddr']
                    and f['protocol'] == protocol
                ]

            for other_flow in matching_flows:
                # Exact port-pair match: ENI sent from dst_port to src_port, now getting reply
                if other_flow['srcport'] == dst_port and other_flow['dstport'] == src_port:
                    return True

            # No exact match found — don't assume it's return traffic.
            # This is intentionally conservative: unmatched flows will be evaluated
            # against security group rules, which is safer than silently ignoring them.
            return False
        except (ValueError, TypeError) as e:
            if self.verbose:
                print(f"Error in return traffic detection: {str(e)}")
            return False

    def is_outbound_return_traffic(self, flow, eni_ip, inbound_index=None):
        """Check if an outbound flow is return traffic for an inbound session.

        Mirror of is_return_traffic but for the outbound direction. Uses the same
        conservative approach: only classifies as return traffic when there is an
        exact port-pair match in the inbound index proving the ENI received an
        inbound request that this outbound flow is responding to.
        """
        try:
            protocol = flow['protocol']
            src_port = flow['srcport']
            dst_port = flow['dstport']

            # ICMP: don't treat as return traffic
            if protocol == 1:
                return False

            # If destination is a well-known server port, the ENI is initiating a
            # connection to a remote service — this is genuine outbound, not return traffic
            if dst_port in self._well_known_ports:
                return False

            # Look for a matching inbound flow with exact port-pair swap
            if inbound_index:
                key = (flow['dstaddr'], protocol)
                matching_flows = inbound_index.get(key, [])
            else:
                matching_flows = []

            for other_flow in matching_flows:
                # Exact port-pair match: someone sent to src_port from dst_port, now ENI replies
                if other_flow['srcport'] == dst_port and other_flow['dstport'] == src_port:
                    return True

            # No exact match — don't assume it's return traffic.
            # Genuine outbound connections will be evaluated against outbound rules.
            return False
        except (ValueError, TypeError) as e:
            if self.verbose:
                print(f"Error in outbound return traffic detection: {str(e)}")
            return False

    def _analyze_outbound(self, flows, eni_ip, outbound_rules, max_flows):
        """Analyze outbound traffic against any:any outbound rules.

        Returns a dict with keys: affected, still_allowed, return_traffic, total_outbound
        """
        any_any_outbound = [rule for rule in outbound_rules if self.is_any_any_rule(rule)]
        other_outbound = [rule for rule in outbound_rules if not self.is_any_any_rule(rule)]

        if not any_any_outbound:
            return None

        # Build inbound flow index for outbound return traffic detection
        inbound_index = self._build_flow_index(flows, eni_ip, direction='inbound')

        affected_flows = []
        still_allowed_flows = []
        return_traffic_flows = []
        outbound_count = 0
        processed = 0

        for flow in flows:
            if flow['action'] != 'ACCEPT' or flow['srcaddr'] != eni_ip:
                continue

            outbound_count += 1
            processed += 1

            if processed > max_flows:
                if self.verbose:
                    print(f"Outbound early termination: processed {processed} flows")
                break

            # Skip return traffic — stateful SGs allow replies automatically
            if self.is_outbound_return_traffic(flow, eni_ip, inbound_index):
                return_traffic_flows.append(flow)
                continue

            # Check if flow is allowed by outbound any:any rule
            allowed_by_any_any = any(
                self.traffic_allowed_by_rule(flow, rule, is_inbound=False)
                for rule in any_any_outbound
            )

            if allowed_by_any_any:
                allowed_by_other = any(
                    self.traffic_allowed_by_rule(flow, rule, is_inbound=False)
                    for rule in other_outbound
                )

                if allowed_by_other:
                    still_allowed_flows.append(flow)
                else:
                    affected_flows.append(flow)

        return {
            'affected': affected_flows,
            'still_allowed': still_allowed_flows,
            'return_traffic': return_traffic_flows,
            'total_outbound': outbound_count,
            'any_any_rules': any_any_outbound,
        }

    def _deduplicate_flows(self, flows):
        """Deduplicate flows by (srcaddr, protocol_name, dstport) and attach counts.

        Returns a list of flow dicts with 'count' and 'flow_key' added, sorted by
        count descending.
        """
        flow_counts = defaultdict(int)
        for flow in flows:
            flow_key = (flow['srcaddr'], flow['protocol_name'], flow['dstport'])
            flow_counts[flow_key] += 1

        seen = set()
        unique_flows = []
        for flow in flows:
            flow_key = (flow['srcaddr'], flow['protocol_name'], flow['dstport'])
            if flow_key not in seen:
                seen.add(flow_key)
                flow_with_count = flow.copy()
                flow_with_count['count'] = flow_counts[flow_key]
                flow_with_count['flow_key'] = flow_key
                unique_flows.append(flow_with_count)

        unique_flows.sort(key=lambda x: x['count'], reverse=True)
        return unique_flows

    def analyze_security_group(self, sg_id, eni_id, hours=24.0, max_flows=10000, analyze_outbound=False):
        """Main analysis function"""
        print(f"Analyzing Security Group: {sg_id}")
        print(f"Network Interface: {eni_id}")
        if hours < 1:
            minutes = int(hours * 60)
            print(f"Flow logs period: {minutes} minutes")
        else:
            print(f"Flow logs period: {hours} hours")
        print(f"Max flows to analyze: {max_flows}")
        print(f"Ephemeral port threshold: {self.ephemeral_port_threshold}")
        print(f"Analyze outbound: {'Yes' if analyze_outbound else 'No'}")
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

        # Calculate actual time range from flow timestamps
        if flows:
            try:
                timestamps = []
                for flow in flows:
                    if '@timestamp' in flow:
                        try:
                            ts = flow.get('@timestamp', '')
                            if '.' in ts:
                                dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
                            else:
                                dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                            timestamps.append(dt)
                        except ValueError:
                            pass

                if timestamps:
                    min_time = min(timestamps)
                    max_time = max(timestamps)
                    actual_hours = round((max_time - min_time).total_seconds() / 3600, 1)
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

        print(f"Retrieved {len(flows)} flow log entries")

        # Get ENI IP address for return traffic detection (uses shared cache)
        eni_info = self._get_eni_info(eni_id)
        eni_ip = eni_info['PrivateIpAddress']

        # Identify any:any rules
        inbound_rules = sg.get('IpPermissions', [])
        outbound_rules = sg.get('IpPermissionsEgress', [])

        any_any_inbound = [rule for rule in inbound_rules if self.is_any_any_rule(rule)]
        other_inbound = [rule for rule in inbound_rules if not self.is_any_any_rule(rule)]

        has_inbound_any_any = bool(any_any_inbound)

        if not has_inbound_any_any and not analyze_outbound:
            print("\nNo inbound any:any rules found in this security group")
            return

        # Build outbound flow index for inbound return traffic detection
        outbound_index = self._build_flow_index(flows, eni_ip, direction='outbound')

        # ── Inbound Analysis ──
        if has_inbound_any_any:
            print(f"\n{'=' * 50}")
            print("INBOUND ANALYSIS")
            print(f"{'=' * 50}")

            affected_flows = []
            still_allowed_flows = []
            return_traffic_flows = []
            inbound_flows = 0
            processed_flows = 0

            for flow in flows:
                if flow['action'] != 'ACCEPT' or flow['dstaddr'] != eni_ip:
                    continue

                inbound_flows += 1
                processed_flows += 1

                if processed_flows > max_flows:
                    if self.verbose:
                        print(f"Early termination: processed {processed_flows} flows")
                    break

                if self.is_return_traffic(flow, flows, eni_ip, outbound_index):
                    return_traffic_flows.append(flow)
                    continue

                allowed_by_any_any = any(
                    self.traffic_allowed_by_rule(flow, rule, is_inbound=True)
                    for rule in any_any_inbound
                )

                if allowed_by_any_any:
                    allowed_by_other = any(
                        self.traffic_allowed_by_rule(flow, rule, is_inbound=True)
                        for rule in other_inbound
                    )

                    if allowed_by_other:
                        still_allowed_flows.append(flow)
                    else:
                        affected_flows.append(flow)

            print(f"\nInbound flows: {inbound_flows} (including {len(return_traffic_flows)} return traffic flows that were excluded)")

            if self.verbose and return_traffic_flows:
                unique_return = self._deduplicate_flows(return_traffic_flows)
                print(f"\nReturn traffic detected ({len(unique_return)} unique combinations, {len(return_traffic_flows)} total flows):")
                print(f"  {'Source IP':<15} {'Protocol':<10} {'Src Port':<10} {'Dest Port':<10} {'Count':<8}")
                print(f"  {'-' * 58}")
                for flow in unique_return[:10]:
                    print(f"  {flow['srcaddr']:<15} {flow['protocol_name']:<10} {flow['srcport']:<10} {flow['dstport']:<10} {flow['count']:<8}")
                if len(unique_return) > 10:
                    print(f"  ... and {len(unique_return) - 10} more unique combinations")

            if affected_flows:
                unique_affected = self._deduplicate_flows(affected_flows)

                print(f"\nInbound traffic that would be BLOCKED after removing inbound any:any rules:")
                print(f"{'Source IP':<15} {'Protocol':<10} {'Dest Port':<10} {'Count':<8}")
                print("-" * 50)
                for flow in unique_affected[:20]:
                    print(f"{flow['srcaddr']:<15} {flow['protocol_name']:<10} {flow['dstport']:<10} {flow['count']:<8}")

                if len(unique_affected) > 20:
                    print(f"... and {len(unique_affected) - 20} more unique flows")
                total_count = sum(flow['count'] for flow in unique_affected)
                print(f"(Total {total_count} flows across {len(unique_affected)} unique combinations)")

            if still_allowed_flows:
                unique_allowed = self._deduplicate_flows(still_allowed_flows)
                print(f"\n{len(unique_allowed)} unique traffic flows would still be allowed by other inbound rules")
                if len(still_allowed_flows) != len(unique_allowed):
                    print(f"(Total {len(still_allowed_flows)} individual flows)")

            if not affected_flows:
                print(f"\n✅ INBOUND RECOMMENDATION: Safe to remove inbound any:any rules")
                if still_allowed_flows:
                    print("All current inbound traffic would still be allowed by other rules")
                else:
                    print("No new inbound connections found - all traffic appears to be return/outbound traffic")
            else:
                print(f"\n⚠️  INBOUND RECOMMENDATION: Review before removing inbound any:any rules")
                print(f"{len(affected_flows)} inbound traffic flows would be blocked")
                print("Consider adding specific inbound rules for the affected traffic first")
        else:
            print("\nNo inbound any:any rules found in this security group")

        # ── Outbound Analysis ──
        if analyze_outbound:
            print(f"\n{'=' * 50}")
            print("OUTBOUND ANALYSIS")
            print(f"{'=' * 50}")

            outbound_rules = sg.get('IpPermissionsEgress', [])
            result = self._analyze_outbound(flows, eni_ip, outbound_rules, max_flows)

            if result is None:
                print("\nNo outbound any:any rules found in this security group")
            else:
                ob_affected = result['affected']
                ob_still_allowed = result['still_allowed']
                ob_return = result['return_traffic']
                ob_total = result['total_outbound']

                print(f"\nOutbound flows: {ob_total} (including {len(ob_return)} return traffic flows that were excluded)")

                if self.verbose and ob_return:
                    unique_return = self._deduplicate_flows(ob_return)
                    print(f"\nOutbound return traffic detected ({len(unique_return)} unique combinations, {len(ob_return)} total flows):")
                    print(f"  {'Dest IP':<15} {'Protocol':<10} {'Src Port':<10} {'Dest Port':<10} {'Count':<8}")
                    print(f"  {'-' * 58}")
                    for flow in unique_return[:10]:
                        print(f"  {flow['dstaddr']:<15} {flow['protocol_name']:<10} {flow['srcport']:<10} {flow['dstport']:<10} {flow['count']:<8}")
                    if len(unique_return) > 10:
                        print(f"  ... and {len(unique_return) - 10} more unique combinations")

                # Check for DNS-related return traffic without corresponding outbound DNS queries
                # DNS queries are outbound UDP to port 53; if these appear as "return traffic"
                # it means the inbound index matched them (likely VPC resolver responses)
                dns_return_flows = [f for f in ob_return if f['protocol'] == 17 and f['dstport'] == 53]
                dns_outbound_from_53 = [f for f in ob_return if f['protocol'] == 17 and f['srcport'] == 53]
                if dns_return_flows or dns_outbound_from_53:
                    # Check if there are any outbound UDP 53 flows in affected or still_allowed
                    has_outbound_dns = any(
                        f['protocol'] == 17 and f['dstport'] == 53
                        for f in ob_affected + ob_still_allowed
                    )
                    if not has_outbound_dns:
                        dns_count = len(dns_return_flows) + len(dns_outbound_from_53)
                        print(f"\nℹ️  NOTE: {dns_count} DNS-related flows were classified as return traffic but no")
                        print("   outbound DNS queries appear in the blocked/allowed results.")
                        print("   This is normal when using the VPC DNS resolver (x.x.x.2) — queries to the")
                        print("   VPC resolver may not appear in flow logs, but responses from upstream")
                        print("   resolvers do. This tool can only analyze traffic visible in flow logs.")

                if ob_affected:
                    unique_affected = self._deduplicate_flows(ob_affected)

                    print(f"\nOutbound traffic that would be BLOCKED after removing outbound any:any rules:")
                    print(f"{'Dest IP':<15} {'Protocol':<10} {'Dest Port':<10} {'Count':<8}")
                    print("-" * 50)
                    for flow in unique_affected[:20]:
                        print(f"{flow['dstaddr']:<15} {flow['protocol_name']:<10} {flow['dstport']:<10} {flow['count']:<8}")

                    if len(unique_affected) > 20:
                        print(f"... and {len(unique_affected) - 20} more unique flows")
                    total_count = sum(flow['count'] for flow in unique_affected)
                    print(f"(Total {total_count} flows across {len(unique_affected)} unique combinations)")

                if ob_still_allowed:
                    unique_allowed = self._deduplicate_flows(ob_still_allowed)
                    print(f"\n{len(unique_allowed)} unique traffic flows would still be allowed by other outbound rules")
                    if len(ob_still_allowed) != len(unique_allowed):
                        print(f"(Total {len(ob_still_allowed)} individual flows)")

                if not ob_affected:
                    print(f"\n✅ OUTBOUND RECOMMENDATION: Safe to remove outbound any:any rules")
                    if ob_still_allowed:
                        print("All current outbound traffic would still be allowed by other rules")
                    else:
                        print("No outbound connections found that depend solely on the any:any rule")
                else:
                    print(f"\n⚠️  OUTBOUND RECOMMENDATION: Review before removing outbound any:any rules")
                    print(f"{len(ob_affected)} outbound traffic flows would be blocked")
                    print("Consider adding specific outbound rules for the affected traffic first")


def main():
    parser = argparse.ArgumentParser(description='Analyze Security Group any:any rules')
    parser.add_argument('--sg-id', required=True, help='Security Group ID')
    parser.add_argument('--eni-id', required=True, help='Network Interface ID')
    parser.add_argument('--hours', type=float, default=24,
                        help='Hours of flow logs to analyze (default: 24, can be decimal like 0.5 for 30 minutes)')
    parser.add_argument('--max-flows', type=int, default=10000,
                        help='Maximum number of flow logs to analyze (default: 10000)')
    parser.add_argument('--ephemeral-port-threshold', type=int, default=DEFAULT_EPHEMERAL_PORT_THRESHOLD,
                        help=f'Port threshold for ephemeral/return traffic detection (default: {DEFAULT_EPHEMERAL_PORT_THRESHOLD})')
    parser.add_argument('--analyze-outbound', action='store_true',
                        help='Also analyze outbound any:any rules (not run by default)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    analyzer = SecurityGroupAnalyzer(
        verbose=args.verbose,
        ephemeral_port_threshold=args.ephemeral_port_threshold
    )
    analyzer.analyze_security_group(
        args.sg_id, args.eni_id, args.hours, args.max_flows,
        analyze_outbound=args.analyze_outbound
    )


if __name__ == "__main__":
    main()
