import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401




class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def syncscanrequest_request(self, tr_id, profile_name, profile_id, app_name, app_user, ai_model, prompt, response, code_prompt, code_response):
        data = {"ai_profile": {"profile_name": profile_name}, "contents": [{"code_prompt": code_prompt, "code_response": code_response, "prompt": prompt, "response": response}], "metadata": {
            "ai_model": ai_model, "app_name": app_name, "app_user": app_user}, "tr_id": tr_id}
        headers = self._headers
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'v1/scan/sync/request', json_data=data, headers=headers)

        return response

    def asyncscanrequest_request(self, req_id, tr_id, profile_name, profile_id, app_name, app_user, ai_model, prompt, response, code_prompt, code_response):
        data = [{"req_id": req_id, "scan_req": {"ai_profile": {"profile_name": profile_name}, "contents": [{"code_prompt": code_prompt, "code_response": code_response,
                                                                                                            "prompt": prompt, "response": response}], "metadata": {"ai_model": ai_model, "app_name": app_name, "app_user": app_user}, "tr_id": tr_id}}]
        headers = self._headers
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'v1/scan/async/request', json_data=data, headers=headers)

        return response

    def scanresultsbyscanid_request(self, scan_ids):
        params = assign_params(scan_ids=scan_ids)
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', 'v1/scan/results', params=params, headers=headers)

        return response

    def scanreportsbyreportid_request(self, report_ids):
        params = assign_params(report_ids=report_ids)
        headers = self._headers
        headers['Accept'] = 'application/json'

        response = self._http_request('GET', 'v1/scan/reports', params=params, headers=headers)

        return response

#def payload_syncscan_max(data)
    # Convert payload to JSON string
    #payload_json = json.dumps(data)

    # Calculate size in bytes
    #payload_size_bytes = len(payload_json.encode('utf-8'))

    # Convert bytes to megabytes (1 MB = 1024 * 1024 bytes)
    #payload_size_mb = payload_size_bytes / (1024 * 1024)

    #print(f"Payload size: {payload_size_mb:.2f} MB")

#def payload_asyncscan_max(data)
    # Convert payload to JSON string
    #payload_json = json.dumps(data)

    # Calculate size in bytes
    #payload_size_bytes = len(payload_json.encode('utf-8'))

    # Convert bytes to megabytes (1 MB = 1024 * 1024 bytes)
    #payload_size_mb = payload_size_bytes / (1024 * 1024)

    #print(f"Payload size: {payload_size_mb:.2f} MB")


def url_asyncscanrequest_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    # create tx id for these batch lookups using current datetime string
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y%m%d%H%M%S")
    tr_id = formatted_time
    profile_name = args.get('url_profile_name')
    app_name = args.get('app_name')
    app_user = args.get('app_user')
    ai_model = args.get('ai_model')
    prompt = args.get('url')

    query_list = {}
    query_list["urls"] = []
    query_list["urls"].append(prompt)

    response = client.asyncscanrequest_request(req_id, tr_id, profile_name, profile_id, app_name, app_user, ai_model, prompt, response, code_prompt, code_response)
    command_results = CommandResults(
        outputs_prefix='URL.Data.',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def syncscanrequest_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tr_id = args.get('tr_id')
    profile_name = args.get('profile_name')
    profile_id = args.get('profile_id')
    app_name = args.get('app_name')
    app_user = args.get('app_user')
    ai_model = args.get('ai_model')
    prompt = args.get('prompt')
    response = args.get('response')
    code_prompt = args.get('code_prompt')
    code_response = args.get('code_response')

    response = client.syncscanrequest_request(tr_id, profile_name, profile_id, app_name,
                                              app_user, ai_model, prompt, response, code_prompt, code_response)
    command_results = CommandResults(
        outputs_prefix='Airsapi.SyncScanRequest',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def asyncscanrequest_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    req_id = args.get('req_id')
    tr_id = args.get('tr_id')
    profile_name = args.get('profile_name')
    profile_id = args.get('profile_id')
    app_name = args.get('app_name')
    app_user = args.get('app_user')
    ai_model = args.get('ai_model')
    prompt = args.get('prompt')
    response = args.get('response')
    code_prompt = args.get('code_prompt')
    code_response = args.get('code_response')

    response = client.asyncscanrequest_request(
        req_id, tr_id, profile_name, profile_id, app_name, app_user, ai_model, prompt, response, code_prompt, code_response)
    command_results = CommandResults(
        outputs_prefix='Airsapi.AsyncScanRequest',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def scanresultsbyscanid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    scan_ids = args.get('scan_ids')

    response = client.scanresultsbyscanid_request(scan_ids)
    command_results = CommandResults(
        outputs_prefix='Airsapi.Scanresultsbyscanid',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def scanreportsbyreportid_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    report_ids = args.get('report_ids')

    response = client.scanreportsbyreportid_request(report_ids)
    command_results = CommandResults(
        outputs_prefix='Airsapi.Scanreportsbyreportid',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    USE_URL_FILTERING: bool = params.get('use_url_filtering', False)

    headers = {}
    headers['x-pan-token'] = params['api_key']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'airsapi-syncscanrequest': syncscanrequest_command,
            'airsapi-asyncscanrequest': asyncscanrequest_command,
            'airsapi-scanresultsbyscanid': scanresultsbyscanid_command,
            'airsapi-scanreportsbyreportid': scanreportsbyreportid_command,
        }

        if command == 'test-module':
            test_module(client)
        # URL Filtering capabilities
        elif command == 'url':
            if USE_URL_FILTERING:  # default is false
                return_results(url_asyncscanrequest_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
