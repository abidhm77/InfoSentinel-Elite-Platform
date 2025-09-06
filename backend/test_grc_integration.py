import unittest
import requests
import json
import time

BASE_URL = 'http://localhost:5001'  # Updated to match server port

class TestGRCIntegration(unittest.TestCase):
    def test_grc_integration(self):
        print('\n=== Testing GRC Integration ===')
        timestamp = str(int(time.time()))
        username = f'testuser_{timestamp}'
        
        # Step 1: Register a test user
        register_payload = {'username': username, 'email': f'test_{timestamp}@example.com', 'password': 'testpass'}
        register_response = requests.post(f'{BASE_URL}/api/auth/register', json=register_payload)
        self.assertEqual(register_response.status_code, 201, f'Registration failed: {register_response.text}')
        
        # Step 2: Login to get token
        login_payload = {'username': username, 'password': 'testpass'}
        login_response = requests.post(f'{BASE_URL}/api/auth/login', json=login_payload)
        self.assertEqual(login_response.status_code, 200, f'Login failed: {login_response.text}')
        token = login_response.json().get('token')
        headers = {'Authorization': f'Bearer {token}'}
        
        # Step 3: Create a scan
        scan_payload = {'target': 'example.com', 'scan_type': 'web'}
        scan_response = requests.post(f'{BASE_URL}/api/scans', json=scan_payload, headers=headers)
        self.assertEqual(scan_response.status_code, 201, f'Scan creation failed: {scan_response.text}')
        scan_id = scan_response.json().get('id')
        print(f'Scan created: {scan_id}')
        
        # Step 4: Wait for scan to complete (simulated)
        time.sleep(5)  # Adjust based on actual scan time
        
        # Step 5: Generate compliance report using POST method
        report_payload = {'format': 'json'}
        report_response = requests.post(f'{BASE_URL}/api/export', json=report_payload, headers=headers)
        self.assertEqual(report_response.status_code, 200, f'Report generation failed: {report_response.text}')
        report = report_response.json()
        print(f'Compliance report generated with status: {report.get("compliance", {}).get("compliance_status")}')
        
        # Verify GRC elements
        self.assertIn('compliance', report, 'Compliance section missing in report')
        self.assertIn(scan_id, [s['id'] for s in report.get('scans', [])], 'Scan not in report')
        print('GRC integration test passed!')

if __name__ == '__main__':
    unittest.main()