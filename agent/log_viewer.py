#!/usr/bin/env python3
"""
Log Viewer - Real-time Health & Metrics Dashboard

Monitors agent logs and displays structured health checks and metrics
in a user-friendly format. No Prometheus needed!

Usage:
    python log_viewer.py [logfile]
    tail -f agent.log | python log_viewer.py
"""

import sys
import json
import re
from datetime import datetime


class LogViewer:
    """Real-time log viewer for structured health and metrics data"""

    def __init__(self):
        self.last_health = None
        self.last_metrics = None

    def parse_line(self, line: str):
        """Parse and display a log line"""
        # Check for structured health check
        if "HEALTH_CHECK:" in line:
            try:
                json_str = line.split("HEALTH_CHECK:")[1].strip()
                data = json.loads(json_str)
                self.display_health_check(data)
                self.last_health = data
            except Exception as e:
                print(f"Error parsing health check: {e}")

        # Check for structured metrics
        elif "METRICS:" in line:
            try:
                json_str = line.split("METRICS:")[1].strip()
                data = json.loads(json_str)
                self.display_metrics(data)
                self.last_metrics = data
            except Exception as e:
                print(f"Error parsing metrics: {e}")

        # Regular log lines
        else:
            # Only print important messages
            if any(keyword in line for keyword in [
                "ERROR", "WARNING", "✓", "✗", "started", "stopped",
                "Rotating", "SVID", "Certificate"
            ]):
                print(line.strip())

    def display_health_check(self, data):
        """Display health check in formatted view"""
        print("\n" + "=" * 70)
        print(f"  HEALTH CHECK - {data['timestamp']}")
        print("=" * 70)

        # Overall status
        status = data['overall_status'].upper()
        symbol = "✓" if status == "HEALTHY" else "✗"
        print(f"\n{symbol} Overall Status: {status}")

        # Component details
        print("\nComponents:")
        for comp_name, comp_data in data['components'].items():
            status_symbol = "✓" if comp_data['status'] == "healthy" else "✗"
            comp_title = comp_name.replace('_', ' ').title()

            print(f"\n  {status_symbol} {comp_title}")
            print(f"     Status: {comp_data['status'].upper()}")
            print(f"     {comp_data['message']}")

            if 'details' in comp_data and comp_data['details']:
                # Show key details
                details = comp_data['details']
                if 'active_svids' in details:
                    print(f"     Active SVIDs: {details['active_svids']}")
                if 'workload_entries' in details:
                    print(f"     Cached Entries: {details['workload_entries']}")
                if 'active_certificates' in details:
                    print(f"     Active Certs: {details['active_certificates']}")
                if 'rotation_failures' in details and details['rotation_failures'] > 0:
                    print(f"     ⚠ Rotation Failures: {details['rotation_failures']}")

        print("\n" + "=" * 70)

    def display_metrics(self, data):
        """Display metrics in formatted view"""
        print("\n" + "=" * 70)
        print(f"  SYSTEM METRICS - {data['timestamp']}")
        print("=" * 70)

        # Calculate uptime
        uptime_sec = data['uptime_seconds']
        hours = uptime_sec // 3600
        minutes = (uptime_sec % 3600) // 60
        secs = uptime_sec % 60

        print(f"\nUptime: {hours}h {minutes}m {secs}s")

        # Workload stats
        print(f"\nWorkloads:")
        print(f"  Tracked: {data['total_workloads']:>6}")
        print(f"  Active SVIDs: {data['active_svids']:>6}")
        print(f"  Cached Entries: {data['workload_entries_cached']:>6}")

        # Certificate stats
        print(f"\nCertificates:")
        print(f"  Total Issued: {data['total_issued']:>6}")
        print(f"  Total Rotated: {data['total_rotated']:>6}")

        if data['rotation_failures'] > 0:
            print(f"  ⚠ Failures: {data['rotation_failures']:>6}")

        if data['avg_rotation_time_ms'] > 0:
            print(f"  Avg Rotation: {data['avg_rotation_time_ms']:>6.1f}ms")

        # API stats
        print(f"\nAPI:")
        print(f"  Total Requests: {data['api_requests_total']:>6}")

        if data['api_errors_total'] > 0:
            error_rate = (data['api_errors_total'] / max(data['api_requests_total'], 1)) * 100
            print(f"  ⚠ Errors: {data['api_errors_total']:>6} ({error_rate:.1f}%)")

        print("\n" + "=" * 70)

    def display_summary(self):
        """Display summary of last known state"""
        if self.last_health or self.last_metrics:
            print("\n" + "=" * 70)
            print("  SUMMARY")
            print("=" * 70)

            if self.last_health:
                status = self.last_health['overall_status'].upper()
                print(f"\nLast Health Check: {status}")

            if self.last_metrics:
                print(f"\nSystem Stats:")
                print(f"  Uptime: {self.last_metrics['uptime_seconds']}s")
                print(f"  Active SVIDs: {self.last_metrics['active_svids']}")
                print(f"  Total Rotated: {self.last_metrics['total_rotated']}")

            print("\n" + "=" * 70)


def main():
    """Main entry point"""
    viewer = LogViewer()

    print("=" * 70)
    print("  ICP Agent Log Viewer")
    print("  Monitoring structured logs for health and metrics...")
    print("=" * 70)

    try:
        # Read from stdin if available, otherwise from file
        if len(sys.argv) > 1:
            logfile = sys.argv[1]
            print(f"\nReading from: {logfile}")
            print("Press Ctrl+C to stop\n")

            with open(logfile, 'r') as f:
                # Read existing lines
                for line in f:
                    viewer.parse_line(line)

                # Follow new lines (like tail -f)
                while True:
                    line = f.readline()
                    if line:
                        viewer.parse_line(line)
                    else:
                        import time
                        time.sleep(0.1)
        else:
            print("\nReading from stdin (pipe logs here)")
            print("Example: tail -f agent.log | python log_viewer.py")
            print("Press Ctrl+C to stop\n")

            for line in sys.stdin:
                viewer.parse_line(line)

    except KeyboardInterrupt:
        print("\n\nStopped by user")
        viewer.display_summary()
    except FileNotFoundError:
        print(f"\nError: File not found: {sys.argv[1]}")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
