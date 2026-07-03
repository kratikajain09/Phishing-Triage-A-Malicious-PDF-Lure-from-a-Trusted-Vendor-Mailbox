# Phishing-Triage-A-Malicious-PDF-Lure-from-a-Trusted-Vendor-Mailbox
Phishing Triage: A Malicious PDF Lure from a Trusted Vendor Mailbox

Phishing Triage: A Malicious PDF Lure from a Trusted Vendor Mailbox
A SOC case study. This writeup documents a phishing investigation using a sanitized, fictionalized version of a real incident. All company names, users, domains, IPs, and identifiers have been replaced with documentation-safe placeholders (Contoso = the defending org, Fabrikam = the vendor, .example domains). No proprietary data from any environment is included. Detection logic and methodology are industry-standard.
________________________________________
TL;DR
A user reported a vendor-themed email carrying a PDF that linked to an invoice-themed landing page. Every "safe" signal pointed the wrong way — SPF and DMARC passed, the sender was a real business partner, and threat intel showed no bad reputation. Those exact signals are why it needed a real investigation rather than a quick close.
The email turned out to be phishing sent from a compromised legitimate vendor mailbox — later confirmed by the vendor. No internal user clicked, no credentials were submitted, and no account was compromised. This case study walks through how that conclusion was reached, the KQL used to prove it, the containment sequence, and — at the end — how the investigation would have escalated if a user had clicked.
Skills demonstrated: email header/authentication analysis · phishing triage · blast-radius scoping · account-compromise review · KQL in Microsoft Sentinel / Defender · containment lifecycle · vendor coordination.
________________________________________
Investigation at a glance
 
The flow above traces the incident end to end: a reported email, triage that surfaced the "clean auth from a trusted vendor" contradiction, blast-radius and account review to rule out impact, external confirmation of vendor mailbox compromise, containment, and a monitored unblock once the vendor remediated. Each phase is detailed below.
________________________________________
Environment
	
SIEM/XDR	Microsoft Sentinel + Microsoft Defender for Office 365
Alert source	User-reported phishing (via report button)
Analyst role	SOC L1, triage and investigation
________________________________________
The alert
A standard business user reported a suspicious inbound email:
•	Sender: vendor.sender@fabrikam-travel.example (display name "External Vendor")
•	Subject: [EXTERNAL] - Document For Review
•	Attachment: Vendor_Document.pdf — a document-review lure with a "click here to open" button
•	Delivery: Delivered to Inbox, not blocked at time of receipt
•	First contact from this sender? No — there was an established communication history
The PDF didn't contain executable malware. It was a lure: the button linked out to an external landing page.
________________________________________
Why this wasn't a quick close
The instinct with a reported phish is to confirm it's bad, purge it, and close. What made this one worth a real investigation is that the easy signals all said safe:
Signal	What it said	Why that's misleading
SPF	Pass	Passes when mail is sent from the domain's authorized infra — including a compromised mailbox on that infra
DMARC	Best-guess pass	Alignment held; tells you nothing about whether the account was hijacked
DKIM	Absent	Slightly lowers assurance, but not disqualifying on its own
Sender domain reputation	Clean	Legitimate corporate domains get abused precisely because they're clean
Business relationship	Real vendor	Trust is the attacker's asset here, not a mitigating factor
The key analytical move: clean authentication does not rule out a compromised-but-legitimate mailbox. A passing SPF/DMARC on a trusted partner domain is exactly the profile of vendor email compromise. That reframed the whole investigation from "is this spoofed?" (answer: no) to "is this a hijacked real account?" (answer: yes).
________________________________________
Investigation
1. Confirm the message and pull its artifacts
Identify the reported message, its recipients, URLs, and delivery disposition.
// Locate the reported message across the org by sender + subject
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress == "vendor.sender@fabrikam-travel.example"
| where Subject has "Document For Review"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,
          DeliveryAction, DeliveryLocation, AuthenticationDetails, NetworkMessageId
| sort by Timestamp desc
What this proves: who received it, where it landed (Inbox vs Junk vs Quarantine), and the authentication verdicts — the starting map for blast radius.
2. Scope blast radius — who else got it, and did anyone click?
The single most important L1 question after "is it malicious": how far did it spread, and did anyone interact?
// Pull URLs embedded in the campaign messages
EmailUrlInfo
| where NetworkMessageId in (
    EmailEvents
    | where SenderFromAddress == "vendor.sender@fabrikam-travel.example"
    | where Subject has "Document For Review"
    | distinct NetworkMessageId
  )
| project NetworkMessageId, Url, UrlDomain
// Did ANY internal user click the campaign URLs? (URL click telemetry)
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has_any ("document-hosting.example", "tracking-example.net")
| project Timestamp, AccountUpn, Url, ActionType, IPAddress
What this proves: In this incident the click query returned zero rows — no internal user clicked. That's the finding that keeps this a near-miss instead of a breach, so it has to be demonstrated, not assumed.
3. Rule out post-delivery account compromise
Even with no clicks, verify the reporting recipient (and any other recipients) show no compromise indicators.
// Sign-in review for the recipient — look for anomalies, impossible travel, MFA failures
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "user1@contoso.example"
| project TimeGenerated, ResultType, AppDisplayName, IPAddress, Location,
          AuthenticationRequirement, RiskLevelDuringSignIn
| sort by TimeGenerated desc
// Check for suspicious mailbox rule creation / forwarding — classic BEC persistence
OfficeActivity
| where TimeGenerated > ago(7d)
| where UserId == "user1@contoso.example"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| project TimeGenerated, Operation, UserId, Parameters
What this proves: MFA enabled, no risky sign-ins, no rogue inbox rules, no password-reset anomalies, corporate-registered device. A handful of failed sign-ins existed but traced to clean sources. Conclusion: no post-delivery compromise on the recipient side.
4. Analyze mail flow for the wider relationship
// Historical inbound/outbound with this sender and domain — establish what "normal" looked like
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress == "vendor.sender@fabrikam-travel.example"
     or RecipientEmailAddress endswith "@fabrikam-travel.example"
| summarize Messages = count() by bin(Timestamp, 1d),
            Direction = iff(SenderFromAddress has "fabrikam-travel", "Inbound", "Outbound")
| sort by Timestamp desc
What this proves: a genuine, ongoing business relationship existed — which is why the lure was credible, and why validating with the business (next step) mattered.
5. Validate with the business, then confirm with the vendor
Threat intel showed the domain clean, so the confirmation had to come from people, not tooling:
•	Internal stakeholders confirmed Fabrikam was a legitimate, expected contact.
•	But they also confirmed the email's content and behavior were abnormal for that vendor.
•	A business contact escalated to the vendor, who confirmed the sending mailbox had been compromised.
That external confirmation closed the loop: this was phishing from a hijacked real mailbox, not a spoof.
________________________________________
Containment
Actions taken (and the order matters — scope before you swing):
1.	Blocked the malicious URL at the web/email security layer.
2.	Blocked the sender address as an immediate containment measure.
3.	Temporarily blocked the sender domain once vendor compromise was suspected — a deliberate, higher-impact step given the real business relationship.
4.	Purged/quarantined related messages across recipients.
5.	Re-verified no click activity and no credential submission org-wide.
6.	Requested vendor remediation confirmation.
Then the part that separates "block and forget" from lifecycle handling:
7.	After the vendor confirmed remediation (sessions revoked, password reset, inbox/forwarding rules audited, suspicious sessions blocked), the domain block was lifted and the sender monitored for a short window.
8.	No further suspicious activity observed → investigation closed.
________________________________________
Timeline
Time	Event
T+0	User reports vendor-themed email with PDF + external URL
T+0	Email, attachment, URLs, headers, auth results reviewed
T+0	URL click telemetry checked — no clicks
T+0	Recipient account reviewed — no compromise indicators
T+1	Vendor business relationship validated internally
T+1	Malicious URL + sender address blocked
T+2	Vendor mailbox compromise suspected; sender domain blocked
T+3–T+5	Additional validation with business + vendor contacts
T+6	Vendor confirms remediation complete
T+7	Sender domain unblocked, monitored
T+9	No further activity — investigation closed
________________________________________
Outcome
•	No internal user clicked the malicious URL.
•	No credential submission observed.
•	No recipient account compromise.
•	No suspicious sign-ins; MFA enabled throughout.
•	Vendor confirmed the compromised mailbox was remediated.
A near-miss that stayed a near-miss because the "safe" signals were treated as a prompt to investigate rather than a reason to close.
________________________________________
What I'd do differently / lessons learned
•	Clean auth is a starting question, not an answer. SPF/DMARC pass on a trusted partner domain is a classic vendor-compromise profile.
•	Trust is the attack surface. The existing relationship made the lure credible; established senders deserve more scrutiny on abnormal behavior, not less.
•	Prove the negative. "No one clicked" is only worth stating if you can show the query that demonstrates it.
•	Containment has a lifecycle. Blocking a real partner domain is disruptive; pairing it with a monitored unblock after confirmed remediation balances safety and business continuity.
________________________________________
Appendix: Escalation branch — if a user had clicked (hypothetical)
This section is a deliberate hypothetical, clearly separated from the real incident above. It documents how the investigation would escalate on a confirmed click, both to show the fuller IR picture and as personal interview prep. None of the below happened in the real case.
If UrlClickEvents had returned a hit for an internal user, the investigation pivots from "scope and contain a lure" to "assume potential credential compromise until disproven":
1.	Identify the click and the user. Capture timestamp, source IP, device, and whether the click reached the credential-harvesting page (redirect chain) versus stopping at the first landing page.
2.	Assume credentials may be submitted. Immediately treat the account as at-risk rather than waiting for proof.
3.	Hunt for credential submission and session abuse:
4.	// Successful sign-ins shortly after the click, especially from new IPs/locations
5.	SigninLogs
6.	| where TimeGenerated > ago(2d)
7.	| where UserPrincipalName == "user1@contoso.example"
8.	| where ResultType == 0
9.	| project TimeGenerated, IPAddress, Location, AppDisplayName,
10.	          RiskLevelDuringSignIn, AuthenticationRequirement
11.	| sort by TimeGenerated asc
12.	// Post-click persistence: new inbox rules or forwarding (BEC hallmark)
13.	OfficeActivity
14.	| where TimeGenerated > ago(2d)
15.	| where UserId == "user1@contoso.example"
16.	| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
17.	| project TimeGenerated, Operation, Parameters
18.	Contain the identity, not just the email: force password reset, revoke active sessions/tokens (token theft survives a password change alone), and review MFA registration for attacker-added methods.
19.	Widen blast radius to every other recipient who clicked, treating each as an independent identity incident.
20.	Escalate to L2 / IR with the account-compromise findings and a clear timeline.
Why the token-revocation detail matters: modern phishing increasingly harvests session tokens, so a password reset alone can leave the attacker with a live session. Revoking sessions is the step juniors most often miss — which is exactly why it's worth documenting here.


