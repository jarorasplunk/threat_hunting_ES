"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'regex_extract_ipv4_1' block
    regex_extract_ipv4_1(container=container)

    return

@phantom.playbook_block()
def regex_extract_ipv4_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("regex_extract_ipv4_1() called")

    playbook_input_threat_match_value = phantom.collect2(container=container, datapath=["playbook_input:threat_match_value"])

    parameters = []

    # build parameters list for 'regex_extract_ipv4_1' call
    for playbook_input_threat_match_value_item in playbook_input_threat_match_value:
        parameters.append({
            "input_string": playbook_input_threat_match_value_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/regex_extract_ipv4", parameters=parameters, name="regex_extract_ipv4_1", callback=filter_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        network_session_as_dest(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def network_session_as_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("network_session_as_dest() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""%%\n| tstats `security_content_summariesonly` count values(All_Sessions.vendor_product) as vendor_product values(All_Sessions.user) as user  values(All_Sessions.user_priority) as user_priority values(All_Sessions.user_category) as user_category values(All_Sessions.duration) as duration values(All_Sessions.dest_ip) as dest_ip values(All_Sessions.dest_nt_host) as dest_nt_host values(All_Sessions.src_ip) as src_ip values(All_Sessions.src_nt_host) as src_nt_host values(All_Sessions.action) as action values(All_Sessions.app) as app values(All_Sessions.protocol) as protocol values(All_Sessions.signature) as signature from datamodel=Network_Sessions.All_Sessions where (All_Sessions.dest_ip=\"{0}\" ) by All_Sessions.dest_ip\n%%\n""",
        parameters=[
            "filtered-data:filter_1:condition_1:regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'network_session_as_dest' call
    for filtered_cf_result_0_item in filtered_cf_result_0:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="network_session_as_dest", assets=["es-ebc"], callback=network_traffic_as_dest)

    return


@phantom.playbook_block()
def network_traffic_as_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("network_traffic_as_dest() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| tstats `security_content_summariesonly` count values(All_Traffic.vendor_product) as vendor_product values(All_Traffic.user) as user values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.src_ip) as src_ip values(All_Traffic.dvc_ip) as dvc_ip values(All_Traffic.action) as action values(All_Traffic.app) as app values(All_Traffic.protocol) as protocol from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip=\"{0}\" ) by All_Traffic.rule\n""",
        parameters=[
            "regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'network_traffic_as_dest' call
    for regex_extract_ipv4_1__result_item in regex_extract_ipv4_1__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="network_traffic_as_dest", assets=["es-ebc"], callback=network_sessions_as_source)

    return


@phantom.playbook_block()
def noop_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("noop_3() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/noop", parameters=parameters, name="noop_3", callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["network_session_as_dest:action_result.summary.total_events", "!=", 0],
            ["network_traffic_as_dest:action_result.summary.total_events", "!=", 0],
            ["network_sessions_as_source:action_result.summary.total_events", "!=", 0],
            ["authentication_failure_count:action_result.summary.total_events", "!=", 0],
            ["authentication_success_as_dest:action_result.summary.total_events", "!=", 0],
            ["web_traffic_as_source_or_dest:action_result.summary.total_events", "!=", 0],
            ["network_traffic_as_source:action_result.summary.total_events", "!=", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        task_note_incident_summary(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["network_session_as_dest:action_result.summary.total_events", "==", 0],
            ["network_traffic_as_dest:action_result.summary.total_events", "==", 0],
            ["network_sessions_as_source:action_result.summary.total_events", "==", 0],
            ["authentication_failure_count:action_result.summary.total_events", "==", 0],
            ["authentication_success_as_dest:action_result.summary.total_events", "==", 0],
            ["web_traffic_as_source_or_dest:action_result.summary.total_events", "==", 0],
            ["network_traffic_as_source:action_result.summary.total_events", "==", 0]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        task_note_incident_summary_no_events(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def network_sessions_as_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("network_sessions_as_source() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| tstats `security_content_summariesonly` count values(All_Sessions.vendor_product) values(All_Sessions.user) values(All_Sessions.user_priority) values(All_Sessions.user_category) values(All_Sessions.duration) values(All_Sessions.dest_ip) values(All_Sessions.dest_nt_host) values(All_Sessions.src_ip) values(All_Sessions.src_nt_host) values(All_Sessions.action) values(All_Sessions.app) values(All_Sessions.protocol) values(All_Sessions.signature) from datamodel=Network_Sessions.All_Sessions where (All_Sessions.src_ip=\"{0}\" ) by All_Sessions.src_ip\n\n""",
        parameters=[
            "regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'network_sessions_as_source' call
    for regex_extract_ipv4_1__result_item in regex_extract_ipv4_1__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="network_sessions_as_source", assets=["es-ebc"], callback=authentication_failure_count)

    return


@phantom.playbook_block()
def authentication_failure_count(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("authentication_failure_count() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| tstats `security_content_summariesonly` count values(Authentication.user) values(Authentication.src_user_id) values(Authentication.user_id) values(Authentication.user_agent) values(Authentication.app) values(Authentication.authentication_method) values(Authentication.authentication_service) values(Authentication.action) values(Authentication.reason) values(Authentication.source) values(Authentication.src) values(Authentication.dest) from datamodel=Authentication where (Authentication.action=\"failure\" AND (Authentication.src=\"{0}\" OR Authentication.dest=\"{0}\")) by Authentication.user, Authentication.dest\n""",
        parameters=[
            "regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'authentication_failure_count' call
    for regex_extract_ipv4_1__result_item in regex_extract_ipv4_1__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="authentication_failure_count", assets=["es-ebc"], callback=authentication_success_as_dest)

    return


@phantom.playbook_block()
def authentication_success_as_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("authentication_success_as_dest() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""\n| tstats `security_content_summariesonly` count values(Authentication.user) values(Authentication.src_user_id) values(Authentication.user_id) values(Authentication.user_agent) values(Authentication.app) values(Authentication.authentication_method) values(Authentication.authentication_service) values(Authentication.action) values(Authentication.reason) values(Authentication.source) values(Authentication.src) values(Authentication.dest) from datamodel=Authentication where ((Authentication.action=\"success\" AND Authentication.src=\"{0}\" OR Authentication.dest=\"{0}\")) by Authentication.user, Authentication.dest\n""",
        parameters=[
            "regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'authentication_success_as_dest' call
    for regex_extract_ipv4_1__result_item in regex_extract_ipv4_1__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="authentication_success_as_dest", assets=["es-ebc"], callback=web_traffic_as_source_or_dest)

    return


@phantom.playbook_block()
def web_traffic_as_source_or_dest(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("web_traffic_as_source_or_dest() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| tstats `security_content_summariesonly` count values(Web.src) values(Web.vendor_product) values(Web.user) values(Web.app) values(Web.category) values(Web.url) values(Web.http_user_agent) values(Web.http_referrer) values(Web.uri_path) values(Web.uri_query) from datamodel=Web.Web where (Web.src=\"{0}\" OR Web.dest=\"{0}\") by Web.dest\n\n""",
        parameters=[
            "regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'web_traffic_as_source_or_dest' call
    for regex_extract_ipv4_1__result_item in regex_extract_ipv4_1__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="web_traffic_as_source_or_dest", assets=["es-ebc"], callback=network_traffic_as_source)

    return


@phantom.playbook_block()
def network_traffic_as_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("network_traffic_as_source() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""\n| tstats `security_content_summariesonly` count values(All_Traffic.vendor_product) values(All_Traffic.user) values(All_Traffic.dest_ip) values(All_Traffic.src_ip) values(All_Traffic.dvc_ip) values(All_Traffic.action) values(All_Traffic.app) values(All_Traffic.protocol) from datamodel=Network_Traffic.All_Traffic where (All_Traffic.src_ip=\"{0}\" ) by All_Traffic.rule\n""",
        parameters=[
            "regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"
        ])

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    parameters = []

    # build parameters list for 'network_traffic_as_source' call
    for regex_extract_ipv4_1__result_item in regex_extract_ipv4_1__result:
        if query_formatted_string is not None:
            parameters.append({
                "query": query_formatted_string,
                "command": "",
                "end_time": "now",
                "start_time": "-1h",
                "search_mode": "smart",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="network_traffic_as_source", assets=["es-ebc"], callback=noop_3)

    return


@phantom.playbook_block()
def task_note_incident_summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("task_note_incident_summary() called")

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])
    network_traffic_as_dest_result_data = phantom.collect2(container=container, datapath=["network_traffic_as_dest:action_result.summary.total_events"], action_results=results)
    network_traffic_as_source_result_data = phantom.collect2(container=container, datapath=["network_traffic_as_source:action_result.summary.total_events"], action_results=results)
    network_sessions_as_source_result_data = phantom.collect2(container=container, datapath=["network_sessions_as_source:action_result.summary.total_events"], action_results=results)
    network_session_as_dest_result_data = phantom.collect2(container=container, datapath=["network_session_as_dest:action_result.summary.total_events"], action_results=results)
    web_traffic_as_source_or_dest_result_data = phantom.collect2(container=container, datapath=["web_traffic_as_source_or_dest:action_result.summary.total_events"], action_results=results)
    authentication_failure_count_result_data = phantom.collect2(container=container, datapath=["authentication_failure_count:action_result.summary.total_events"], action_results=results)
    authentication_success_as_dest_result_data = phantom.collect2(container=container, datapath=["authentication_success_as_dest:action_result.summary.total_events"], action_results=results)

    regex_extract_ipv4_1_data_extracted_ipv4 = [item[0] for item in regex_extract_ipv4_1__result]
    network_traffic_as_dest_summary_total_events = [item[0] for item in network_traffic_as_dest_result_data]
    network_traffic_as_source_summary_total_events = [item[0] for item in network_traffic_as_source_result_data]
    network_sessions_as_source_summary_total_events = [item[0] for item in network_sessions_as_source_result_data]
    network_session_as_dest_summary_total_events = [item[0] for item in network_session_as_dest_result_data]
    web_traffic_as_source_or_dest_summary_total_events = [item[0] for item in web_traffic_as_source_or_dest_result_data]
    authentication_failure_count_summary_total_events = [item[0] for item in authentication_failure_count_result_data]
    authentication_success_as_dest_summary_total_events = [item[0] for item in authentication_success_as_dest_result_data]

    task_note_incident_summary__datamodel_note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    note = (
        "\n**Datamodel events summary**\n"
            "| Event type | Number of results |\n"
            "| :--- | :--- |\n"
        )
    note += "|{}|{}|\n".format("Datamodel: Network Traffic events with Threat IP as DESTINATION", network_traffic_as_dest_summary_total_events)
    note += "|{}|{}|\n".format("Datamodel: Network Traffic events with Threat IP as SOURCE", network_traffic_as_source_summary_total_events)
    note += "|{}|{}|\n".format("Datamodel: Network Session events with Threat IP as SOURCE", network_sessions_as_source_summary_total_events)
    note += "|{}|{}|\n".format("Datamodel: Network Session events with Threat IP as DESTINATION", network_session_as_dest_summary_total_events)
    note += "|{}|{}|\n".format("Datamodel: Web events with Threat IP as SOURCE or DEST", web_traffic_as_source_or_dest_summary_total_events)
    note += "|{}|{}|\n".format("Datamodel: Authentication FAILED events from Threat IP", authentication_failure_count_summary_total_events)
    note += "|{}|{}|\n".format("Datamodel: Authentication SUCCESSFUL events from Threat IP", authentication_success_as_dest_summary_total_events)
    
    task_note_incident_summary__datamodel_note_content = note
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="task_note_incident_summary:datamodel_note_content", value=json.dumps(task_note_incident_summary__datamodel_note_content))

    return


@phantom.playbook_block()
def task_note_incident_summary_no_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("task_note_incident_summary_no_events() called")

    regex_extract_ipv4_1__result = phantom.collect2(container=container, datapath=["regex_extract_ipv4_1:custom_function_result.data.extracted_ipv4"])

    regex_extract_ipv4_1_data_extracted_ipv4 = [item[0] for item in regex_extract_ipv4_1__result]

    task_note_incident_summary_no_events__datamodel_note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    note = (
        "\n**Datamodel events summary**\n"
            "| Event type | Number of results |\n"
            "| :--- | :--- |\n"
        )
    note += "|{}|{}|\n".format("Datamodel: Network Traffic events with Threat IP as DESTINATION", "0")
    note += "|{}|{}|\n".format("Datamodel: Network Traffic events with Threat IP as SOURCE", "0")
    note += "|{}|{}|\n".format("Datamodel: Network Session events with Threat IP as SOURCE", "0")
    note += "|{}|{}|\n".format("Datamodel: Network Session events with Threat IP as DESTINATION", "0")
    note += "|{}|{}|\n".format("Datamodel: Web events with Threat IP as SOURCE or DEST", "0")
    note += "|{}|{}|\n".format("Datamodel: Authentication FAILED events from Threat IP", "0")
    note += "|{}|{}|\n".format("Datamodel: Authentication SUCCESSFUL events from Threat IP", "0")
    
    task_note_incident_summary__datamodel_note_content = note

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="task_note_incident_summary_no_events:datamodel_note_content", value=json.dumps(task_note_incident_summary_no_events__datamodel_note_content))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    task_note_incident_summary__datamodel_note_content = json.loads(_ if (_ := phantom.get_run_data(key="task_note_incident_summary:datamodel_note_content")) != "" else "null")  # pylint: disable=used-before-assignment
    task_note_incident_summary_no_events__datamodel_note_content = json.loads(_ if (_ := phantom.get_run_data(key="task_note_incident_summary_no_events:datamodel_note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "task_note_datamodel_summary": task_note_incident_summary__datamodel_note_content,
        "task_note_datamodel_summary_nodata": task_note_incident_summary_no_events__datamodel_note_content,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return