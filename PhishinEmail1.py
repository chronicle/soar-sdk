{
	"Cases": [{
		"Events": [{
			"_fields": {
				"BaseEventIds": "[]",
				"ParentEventId": -1,
				"DeviceProduct": "Phishing email detector"
			},
			"_rawDataFields": {
				"sourcetype": "Phishing email detector",
				"DeviceVendor": "Email server",
				"StartTime": "1498647816000",
				"EndTime": "1498647816000",
				"EventId": "220",
				"Name": "Your New Salary Notification",
				"Mail_OriginalEmailBody": "Hello, You have an important email from the Human Resources Department with regards to your December 2015 Paycheck\r\n\r\nThis email is enclosed in the Marquette University secure network, hence access it below\r\n\r\nAccess the documents here <http://markossolomon.com/F1q7QX.php<link removed>\r\n\r\n***Ensure your login credentials are correct to avoid cancellations**\r\n\r\nFaithfully \r\nHuman Resources \r\nUniversity of California, Berkeley\r\n\r",
				"Severity": "High",
				"CategoryOutcome": "allowed",
				"DeviceEventClassId": "Email check",
				"SourceUserName": "f.attacker4@gmail.com",
				"DestinationUserName": "vickie.b@siemplify.co",
				"DestinationURL": "http://markossolomon.com/F1q7QX.php",
				"sentTime": "1498647816000",
				"message_id": "220",
				"subject": "Your New Salary Notification",
				"body": "Hello, You have an important email from the Human Resources Department with regards to your December 2015 Paycheck\r\n\r\nThis email is enclosed in the Marquette University secure network, hence access it below\r\n\r\nAccess the documents here <http://markossolomon.com/F1q7QX.php<link removed>\r\n\r\n***Ensure your login credentials are correct to avoid cancellations**\r\n\r\nFaithfully \r\nHuman Resources \r\nUniversity of California, Berkeley\r\n\r"
			}
		}],
		"Environment": null,
		"SourceSystemName": "Splunk",
		"TicketId": "220",
		"Description": "The email from <f.attacker4@gmail.com> to <vickie.b@siemplify.co> detected as phishing email.",
		"DisplayId": "125fc5df-31d0-4018-a1d0-d13dc0def50b",
		"Reason": "Phishing email detector",
		"Name": "Suspicious phishing email",
		"DeviceVendor": "Email server",
		"DeviceProduct": "Phishing email detector",
		"StartTime": "1498647816000",
		"EndTime": "1498647816000",
		"Priority": 60,
		"RuleGenerator": "Phishing email detector",
		"Extensions": [],
		"IsTestCase": false
	}]
}