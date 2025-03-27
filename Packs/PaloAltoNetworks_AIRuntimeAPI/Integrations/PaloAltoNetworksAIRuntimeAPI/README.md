v0.3 Integration
AI Runtime Security: API Intercept

This collection provides endpoints to interact with Palo Alto Networks AI Runtime Security (AIRS) service. The API intercept allows you to scan and monitor AI interactions to detect various security threats including prompt injection, malicious URLs, sensitive data exposure, toxic content, malicious code, and more.
This integration was integrated and tested with version xx of PaloAltoNetworksAIRuntimeAPI.

## Configure Palo Alto Networks AI Runtime API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| API Key |  | True |
| AIRS API Profile Name for URL Lookups |  | False |
| Use URL Filtering for auto enrichment | If selected, when running the \!url command, the command will execute using pan-os with PAN_DB \(with applied filters\). The URL filtering categories determine DBot score \(malicious, suspicious, benign\). | False |
| Source Reliability |  | False |
| Predefined Suspicious Categories |  | False |
| Predefined Malicious Categories |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### airsapi-syncscanrequest

***
Scan Synchronous RequestThis endpoint allows you to make a synchronous scan request for detecting malicious content in the provided input

#### Base Command

`airsapi-syncscanrequest`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tr_id | No description provided. | Optional | 
| profile_name | No description provided. | Optional | 
| profile_id | No description provided. | Optional | 
| app_name | No description provided. Default is XSOAR-Integration. | Optional | 
| app_user | No description provided. Default is XSOAR. | Optional | 
| ai_model | No description provided. | Optional | 
| prompt | No description provided. | Optional | 
| response | No description provided. | Optional | 
| code_prompt | No description provided. | Optional | 
| code_response | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Airsapi.SyncScanRequest.error.message | String |  | 
| Airsapi.SyncScanRequest.error.retry_after.interval | Number |  | 
| Airsapi.SyncScanRequest.error.retry_after.unit | String |  | 
| Airsapi.SyncScanRequest.profile_name | string | profile_name | 
| Airsapi.SyncScanRequest.profile_id | string | profile_id | 
| Airsapi.SyncScanRequest.report_id | string | report_id | 
| Airsapi.SyncScanRequest.action | string | action | 
| Airsapi.SyncScanRequest.tr_id | string | tr_id | 
| Airsapi.SyncScanRequest.scan_id | string | scan_id | 
| Airsapi.SyncScanRequest.category | string | category | 
| Airsapi.SyncScanRequest.prompt_detected | unknown | prompt_detected | 
| Airsapi.SyncScanRequest.prompt_detected.db_security | boolean | db_security | 
| Airsapi.SyncScanRequest.prompt_detected.dlp | boolean | dlp | 
| Airsapi.SyncScanRequest.prompt_detected.tocix_content | boolean | toxic_content | 
| Airsapi.SyncScanRequest.prompt_detected.url_cats | boolean | url_cats | 
| Airsapi.SyncScanRequest.response_detected.dlp | unknown | response_Detected | 
| Airsapi.SyncScanRequest.response_detected.dlp | boolean | dlp | 
| Airsapi.SyncScanRequest.response_detected.injection | boolean | injection | 
| Airsapi.SyncScanRequest.response_detected.toxic_content | boolean | toxic_content | 
| Airsapi.SyncScanRequest.response_detected.url_cats | boolean | url_cats | 

### airsapi-asyncscanrequest

***
Scan Async RequestThis endpoint allows you to submit a scan request asynchronously.

#### Base Command

`airsapi-asyncscanrequest`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| req_id | No description provided. | Optional | 
| tr_id | No description provided. | Optional | 
| profile_name | No description provided. | Optional | 
| profile_id | No description provided. | Optional | 
| app_name | No description provided. Default is XSOAR-Integration. | Optional | 
| app_user | No description provided. Default is XSOAR. | Optional | 
| ai_model | No description provided. | Optional | 
| prompt | No description provided. | Optional | 
| response | No description provided. | Optional | 
| code_prompt | No description provided. | Optional | 
| code_response | No description provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Airsapi.AsyncScanRequest.received | Date | recieved | 
| Airsapi.AsyncScanRequest.report_id | String | report_id | 
| Airsapi.AsyncScanRequest.scan_id | String | scan_id | 

### airsapi-scanresultsbyscanid

***
Scan ResultsThis endpoint retrieves the results of a scan based on the provided scan ID.

#### Base Command

`airsapi-scanresultsbyscanid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_ids | No description provided. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Airsapi.Scanresultsbyscanid.req_id | Number | req_id | 
| Airsapi.Scanresultsbyscanid.result.action | String | action | 
| Airsapi.Scanresultsbyscanid.result.category | String | category | 
| Airsapi.Scanresultsbyscanid.result.completed_at | Date | completed_at | 
| Airsapi.Scanresultsbyscanid.result.profile_id | String | profile_id | 
| Airsapi.Scanresultsbyscanid.result.profile_name | String | profile_name | 
| Airsapi.Scanresultsbyscanid.result.prompt_detected.dlp | Boolean | dlp | 
| Airsapi.Scanresultsbyscanid.result.prompt_detected.injection | Boolean | injection | 
| Airsapi.Scanresultsbyscanid.result.prompt_detected.malicious_code | Boolean | malicous_code | 
| Airsapi.Scanresultsbyscanid.result.prompt_detected.toxic_content | Boolean | toxic_content | 
| Airsapi.Scanresultsbyscanid.result.prompt_detected.url_cats | Boolean | url_cats | 
| Airsapi.Scanresultsbyscanid.result.report_id | String | report_id | 
| Airsapi.Scanresultsbyscanid.result.response_detected.db_security | Boolean | db_security | 
| Airsapi.Scanresultsbyscanid.result.response_detected.dlp | Boolean | dlp | 
| Airsapi.Scanresultsbyscanid.result.response_detected.malicious_code | Boolean | malicious_code | 
| Airsapi.Scanresultsbyscanid.result.response_detected.toxic_content | Boolean | toxic_content | 
| Airsapi.Scanresultsbyscanid.result.response_detected.url_cats | Boolean | url_cats | 
| Airsapi.Scanresultsbyscanid.result.scan_id | String | scan_id | 
| Airsapi.Scanresultsbyscanid.result.tr_id | String | tr_id | 
| Airsapi.Scanresultsbyscanid.scan_id | String | scan_id | 
| Airsapi.Scanresultsbyscanid.status | String | status | 

### airsapi-scanreportsbyreportid

***
Get Scan ReportsThis endpoint retrieves scan reports based on the provided report IDs.

#### Base Command

`airsapi-scanreportsbyreportid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_ids | No description provided. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Airsapi.Scanreportsbyreportid.detection_results.action | String | action | 
| Airsapi.Scanreportsbyreportid.detection_results.data_type | String | data_type | 
| Airsapi.Scanreportsbyreportid.detection_results.detection_service | String | detection_service | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dlp_report.data_pattern_rule1_verdict | String | data_pattern_rule1_verdict | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dlp_report.data_pattern_rule2_verdict | String | data_pattern_rule2_verdict | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dlp_report.dlp_profile_id | String | dlp_profile_id | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dlp_report.dlp_profile_name | String | dlp_profile_name | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dlp_report.dlp_report_id | String | dlp_report_id | 
| Airsapi.Scanreportsbyreportid.detection_results.verdict | String | verdict | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.mc_report.code_info | Unknown | code_info | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.mc_report.verdict | String | verdict | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail | Unknown | result_detail | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.tc_report.confidence | String | confidence | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.tc_report.verdict | String | verdict | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.urlf_report.action | String | action | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.urlf_report.categories | String | categories | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.urlf_report.risk_level | String | risk_level | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.urlf_report.url | String | url | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dbs_report.action | String | action | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dbs_report.sub_type | String | sub_type | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.dbs_report.verdict | String | verdict | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.mc_report.code_info.code_sha256 | String | code_sha256 | 
| Airsapi.Scanreportsbyreportid.detection_results.result_detail.mc_report.code_info.file_type | String | file_type | 
| Airsapi.Scanreportsbyreportid.report_id | String | report_id | 
| Airsapi.Scanreportsbyreportid.req_id | Number | req_id | 
| Airsapi.Scanreportsbyreportid.scan_id | String | scan_id | 
| Airsapi.Scanreportsbyreportid.transaction_id | String | transaction_id | 

### url

***
Gets a URL category from URL filtering.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Requested URL. | Required | 

#### Context Output

There is no context output for this command.
