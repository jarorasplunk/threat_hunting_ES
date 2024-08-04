"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_incident_1' block
    get_incident_1(container=container)

    return

@phantom.playbook_block()
def get_incident_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_incident_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    external_id_value = container.get("external_id", None)

    parameters = []

    if external_id_value is not None:
        parameters.append({
            "id": external_id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get incident", parameters=parameters, name="get_incident_1", assets=["builtin_mc_connector"], callback=get_phase_1)

    return


@phantom.playbook_block()
def get_phase_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_phase_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.display_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_phase_1' call
    for get_incident_1_result_item in get_incident_1_result_data:
        if get_incident_1_result_item[0] is not None:
            parameters.append({
                "id": get_incident_1_result_item[0],
                "context": {'artifact_id': get_incident_1_result_item[1], 'artifact_external_id': get_incident_1_result_item[2]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get phase", parameters=parameters, name="get_phase_1", assets=["builtin_mc_connector"], callback=get_task_1)

    return


@phantom.playbook_block()
def get_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_task_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.display_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.tasks.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_task_1' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for get_phase_1_result_item in get_phase_1_result_data:
            if get_incident_1_result_item[0] is not None and get_phase_1_result_item[0] is not None:
                parameters.append({
                    "id": get_incident_1_result_item[0],
                    "task_id": get_phase_1_result_item[0],
                    "context": {'artifact_id': get_phase_1_result_item[1], 'artifact_external_id': get_phase_1_result_item[2]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get task", parameters=parameters, name="get_task_1", assets=["builtin_mc_connector"], callback=get_splunk_index)

    return


@phantom.playbook_block()
def add_task_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# Event summary from datamodels containing {0}:\n""",
        parameters=[
            "container:data.summary.threat_match_value"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""{0}""",
        parameters=[
            "playbook_datamodel_events_enrichment_from_es_1:playbook_output:task_note_datamodel_summary"
        ])

    data_summary_threat_match_value_value = container.get("data", {}).get("summary", {}).get("threat_match_value", None)
    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    playbook_datamodel_events_enrichment_from_es_1_output_task_note_datamodel_summary = phantom.collect2(container=container, datapath=["playbook_datamodel_events_enrichment_from_es_1:playbook_output:task_note_datamodel_summary"])
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_2' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for playbook_datamodel_events_enrichment_from_es_1_output_task_note_datamodel_summary_item in playbook_datamodel_events_enrichment_from_es_1_output_task_note_datamodel_summary:
            for get_task_1_result_item in get_task_1_result_data:
                for get_phase_1_result_item in get_phase_1_result_data:
                    if get_incident_1_result_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                        parameters.append({
                            "id": get_incident_1_result_item[0],
                            "title": title_formatted_string,
                            "content": content_formatted_string,
                            "task_id": get_task_1_result_item[0],
                            "phase_id": get_phase_1_result_item[0],
                            "response_plan_id": get_incident_1_result_item[1],
                            "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_2", assets=["builtin_mc_connector"], callback=update_incidents_2)

    return


@phantom.playbook_block()
def update_incidents_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_incidents_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.owner","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_incidents_2' call
    for get_task_1_result_item in get_task_1_result_data:
        for get_incident_1_result_item in get_incident_1_result_data:
            if get_incident_1_result_item[0] is not None:
                parameters.append({
                    "urgency": "high",
                    "assignee": get_task_1_result_item[0],
                    "incident_id": get_incident_1_result_item[0],
                    "context": {'artifact_id': get_incident_1_result_item[1], 'artifact_external_id': get_incident_1_result_item[2]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update incidents", parameters=parameters, name="update_incidents_2", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def get_splunk_index(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_splunk_index() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""| stats values(index) as index by sourcetype\n| eval index=mvjoin(index,\",\")\n""",
        parameters=[])
    command_formatted_string = phantom.format(
        container=container,
        template="""| tstats count WHERE index=* AND sourcetype IN ({0}) by index sourcetype \n""",
        parameters=[
            "container:data.summary.orig_sourcetype"
        ])

    data_summary_orig_sourcetype_value = container.get("data", {}).get("summary", {}).get("orig_sourcetype", None)

    parameters = []

    if query_formatted_string is not None and command_formatted_string is not None:
        parameters.append({
            "query": query_formatted_string,
            "command": command_formatted_string,
            "display": "index,sourcetype",
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

    phantom.act("run query", parameters=parameters, name="get_splunk_index", assets=["es-ebc"], callback=get_triggered_event_details)

    return


@phantom.playbook_block()
def get_triggered_event_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_triggered_event_details() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    query_formatted_string = phantom.format(
        container=container,
        template="""index IN ({0}) sourcetype IN ({1}) \"{2}\"\n| `add_events({3})`\n| eval dest=if((dest=\"-\" OR dest=\"\"),dest_ip,dest) \n| rename s_computername as computername \n| fields sourcetype action app application app:* client_ip client_location server_ip server_location signature dest dest_port dest_hostname dest_location dest_zone src src_ip src_location src_port src_zone src_user user direction dvc dvc_name computername site http_method http_user_agent http_category http_referer http_referrer http_referrer_name http_referrer_domain log_type rule status status_description url file_hash file_name vendor_product\n| table sourcetype action app application app:* client_ip client_location server_ip server_location signature dest dest_port dest_hostname dest_location dest_zone src src_ip src_location src_port src_zone src_user user direction dvc dvc_name computername site http_method http_user_agent http_category http_referer http_referrer http_referrer_name http_referrer_domain log_type rule status status_description url file_hash file_name vendor_product""",
        parameters=[
            "get_splunk_index:action_result.data.*.index",
            "container:data.summary.orig_sourcetype",
            "container:data.summary.threat_match_value",
            "get_incident_1:action_result.data.*.display_id",
            "get_incident_1:action_result.data.*.id"
        ])

    data_summary_orig_sourcetype_value = container.get("data", {}).get("summary", {}).get("orig_sourcetype", None)
    data_summary_threat_match_value_value = container.get("data", {}).get("summary", {}).get("threat_match_value", None)
    get_splunk_index_result_data = phantom.collect2(container=container, datapath=["get_splunk_index:action_result.data.*.index","get_splunk_index:action_result.parameter.context.artifact_id","get_splunk_index:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.display_id","get_incident_1:action_result.data.*.id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_triggered_event_details' call
    for get_splunk_index_result_item in get_splunk_index_result_data:
        for get_incident_1_result_item in get_incident_1_result_data:
            if query_formatted_string is not None:
                parameters.append({
                    "query": query_formatted_string,
                    "command": "| search",
                    "display": "sourcetype,action,app,application ,client_ip,client_location,server_ip,server_location ,signature ,dest ,dest_port ,dest_hostname ,dest_location ,dest_zone ,src ,src_ip ,src_location ,src_port ,src_zone ,src_user ,user ,direction ,dvc ,dvc_name ,computername ,site ,http_method ,http_user_agent ,http_category ,http_referer ,http_referrer ,http_referrer_name ,http_referrer_domain ,log_type ,rule ,status ,status_description ,url ,file_hash ,file_name ,vendor_product",
                    "end_time": "now",
                    "start_time": "-2h",
                    "search_mode": "verbose",
                    "attach_result": False,
                    "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_triggered_event_details", assets=["es-ebc"], callback=get_triggered_event_details_callback)

    return


@phantom.playbook_block()
def get_triggered_event_details_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_triggered_event_details_callback() called")

    
    add_task_note_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    noop_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    noop_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    playbook_trustar_enrichment_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def playbook_datamodel_events_enrichment_from_es_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_datamodel_events_enrichment_from_es_1() called")

    data_summary_threat_match_value_value = container.get("data", {}).get("summary", {}).get("threat_match_value", None)

    threat_match_value_combined_value = phantom.concatenate(data_summary_threat_match_value_value, dedup=True)

    inputs = {
        "threat_match_value": threat_match_value_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/Datamodel events enrichment from ES", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/Datamodel events enrichment from ES", container=container, name="playbook_datamodel_events_enrichment_from_es_1", callback=decision_2, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_indicators_enrichment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_indicators_enrichment_1() called")

    data_summary_threat_match_value_value = container.get("data", {}).get("summary", {}).get("threat_match_value", None)

    indicators_combined_value = phantom.concatenate(data_summary_threat_match_value_value, dedup=True)

    inputs = {
        "indicators": indicators_combined_value,
        "indicator_type": ["ip"],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/indicators_enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/indicators_enrichment", container=container, name="playbook_indicators_enrichment_1", callback=add_task_note_8, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_assets_and_identities_enrichment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_assets_and_identities_enrichment_1() called")

    get_triggered_event_details_result_data = phantom.collect2(container=container, datapath=["get_triggered_event_details:action_result.data.*.src","get_triggered_event_details:action_result.data.*.dest","get_triggered_event_details:action_result.data.*.user","get_triggered_event_details:action_result.data.*.src_ip","get_triggered_event_details:action_result.data.*.src_user","get_triggered_event_details:action_result.data.*.computername","get_triggered_event_details:action_result.data.*.dest_hostname"], action_results=results)

    get_triggered_event_details_result_item_0 = [item[0] for item in get_triggered_event_details_result_data]
    get_triggered_event_details_result_item_1 = [item[1] for item in get_triggered_event_details_result_data]
    get_triggered_event_details_result_item_2 = [item[2] for item in get_triggered_event_details_result_data]
    get_triggered_event_details_result_item_3 = [item[3] for item in get_triggered_event_details_result_data]
    get_triggered_event_details_result_item_4 = [item[4] for item in get_triggered_event_details_result_data]
    get_triggered_event_details_result_item_5 = [item[5] for item in get_triggered_event_details_result_data]
    get_triggered_event_details_result_item_6 = [item[6] for item in get_triggered_event_details_result_data]

    src_combined_value = phantom.concatenate(get_triggered_event_details_result_item_0, dedup=True)
    dest_combined_value = phantom.concatenate(get_triggered_event_details_result_item_1, dedup=True)
    user_combined_value = phantom.concatenate(get_triggered_event_details_result_item_2, dedup=True)
    src_ip_combined_value = phantom.concatenate(get_triggered_event_details_result_item_3, dedup=True)
    src_user_combined_value = phantom.concatenate(get_triggered_event_details_result_item_4, dedup=True)
    computername_combined_value = phantom.concatenate(get_triggered_event_details_result_item_5, dedup=True)
    dest_hostname_combined_value = phantom.concatenate(get_triggered_event_details_result_item_6, dedup=True)

    inputs = {
        "src": src_combined_value,
        "dest": dest_combined_value,
        "user": user_combined_value,
        "src_ip": src_ip_combined_value,
        "src_user": src_user_combined_value,
        "computername": computername_combined_value,
        "dest_hostname": dest_hostname_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/assets_and_identities_enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/assets_and_identities_enrichment", container=container, name="playbook_assets_and_identities_enrichment_1", callback=decision_1, inputs=inputs)

    return


@phantom.playbook_block()
def add_task_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# Identity details\n""",
        parameters=[])

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    playbook_assets_and_identities_enrichment_1_output_task_note_identity = phantom.collect2(container=container, datapath=["playbook_assets_and_identities_enrichment_1:playbook_output:task_note_identity"])
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_1' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for playbook_assets_and_identities_enrichment_1_output_task_note_identity_item in playbook_assets_and_identities_enrichment_1_output_task_note_identity:
            for get_task_1_result_item in get_task_1_result_data:
                for get_phase_1_result_item in get_phase_1_result_data:
                    if get_incident_1_result_item[0] is not None and title_formatted_string is not None and playbook_assets_and_identities_enrichment_1_output_task_note_identity_item[0] is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                        parameters.append({
                            "id": get_incident_1_result_item[0],
                            "title": title_formatted_string,
                            "content": playbook_assets_and_identities_enrichment_1_output_task_note_identity_item[0],
                            "task_id": get_task_1_result_item[0],
                            "phase_id": get_phase_1_result_item[0],
                            "response_plan_id": get_incident_1_result_item[1],
                            "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(get_incident_1_result_data)
    phantom.debug(playbook_assets_and_identities_enrichment_1_output_task_note_identity)
    phantom.debug(get_task_1_result_data)
    phantom.debug(get_phase_1_result_data)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_1", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def add_task_note_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_8() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    playbook_indicators_enrichment_1_output_note_title = phantom.collect2(container=container, datapath=["playbook_indicators_enrichment_1:playbook_output:note_title"])
    playbook_indicators_enrichment_1_output_note_content = phantom.collect2(container=container, datapath=["playbook_indicators_enrichment_1:playbook_output:note_content"])
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_8' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for playbook_indicators_enrichment_1_output_note_title_item in playbook_indicators_enrichment_1_output_note_title:
            for playbook_indicators_enrichment_1_output_note_content_item in playbook_indicators_enrichment_1_output_note_content:
                for get_task_1_result_item in get_task_1_result_data:
                    for get_phase_1_result_item in get_phase_1_result_data:
                        if get_incident_1_result_item[0] is not None and playbook_indicators_enrichment_1_output_note_title_item[0] is not None and playbook_indicators_enrichment_1_output_note_content_item[0] is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                            parameters.append({
                                "id": get_incident_1_result_item[0],
                                "title": playbook_indicators_enrichment_1_output_note_title_item[0],
                                "content": playbook_indicators_enrichment_1_output_note_content_item[0],
                                "task_id": get_task_1_result_item[0],
                                "phase_id": get_phase_1_result_item[0],
                                "response_plan_id": get_incident_1_result_item[1],
                                "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug(parameters)
    phantom.debug(get_incident_1_result_data)
    phantom.debug(playbook_indicators_enrichment_1_output_note_title)
    phantom.debug(playbook_indicators_enrichment_1_output_note_content)
    phantom.debug(get_task_1_result_data)
    phantom.debug(get_phase_1_result_data)
    
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_8", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def add_task_note_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_7() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# Asset details\n""",
        parameters=[])

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    playbook_assets_and_identities_enrichment_1_output_task_note_assets = phantom.collect2(container=container, datapath=["playbook_assets_and_identities_enrichment_1:playbook_output:task_note_assets"])
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_7' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for playbook_assets_and_identities_enrichment_1_output_task_note_assets_item in playbook_assets_and_identities_enrichment_1_output_task_note_assets:
            for get_task_1_result_item in get_task_1_result_data:
                for get_phase_1_result_item in get_phase_1_result_data:
                    if get_incident_1_result_item[0] is not None and title_formatted_string is not None and playbook_assets_and_identities_enrichment_1_output_task_note_assets_item[0] is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                        parameters.append({
                            "id": get_incident_1_result_item[0],
                            "title": title_formatted_string,
                            "content": playbook_assets_and_identities_enrichment_1_output_task_note_assets_item[0],
                            "task_id": get_task_1_result_item[0],
                            "phase_id": get_phase_1_result_item[0],
                            "response_plan_id": get_incident_1_result_item[1],
                            "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(get_incident_1_result_data)
    phantom.debug(playbook_assets_and_identities_enrichment_1_output_task_note_assets)
    phantom.debug(get_task_1_result_data)
    phantom.debug(get_phase_1_result_data)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_7", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def add_task_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_3' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for get_task_1_result_item in get_task_1_result_data:
            for get_phase_1_result_item in get_phase_1_result_data:
                if get_incident_1_result_item[0] is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                    parameters.append({
                        "id": get_incident_1_result_item[0],
                        "title": "# Associated events",
                        "content": "All associated events triggering this incident have been added to the Events tab. Please review the raw events for investigation.",
                        "task_id": get_task_1_result_item[0],
                        "phase_id": get_phase_1_result_item[0],
                        "response_plan_id": get_incident_1_result_item[1],
                        "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_3", assets=["builtin_mc_connector"], callback=playbook_indicators_enrichment_1)

    return


@phantom.playbook_block()
def noop_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("noop_1() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/noop", parameters=parameters, name="noop_1", callback=playbook_assets_and_identities_enrichment_1)

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

    phantom.custom_function(custom_function="community/noop", parameters=parameters, name="noop_3", callback=playbook_datamodel_events_enrichment_from_es_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_assets_and_identities_enrichment_1:playbook_output:task_note_identity", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_task_note_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_assets_and_identities_enrichment_1:playbook_output:task_note_assets", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        add_task_note_7(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_task_note_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_4() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    title_formatted_string = phantom.format(
        container=container,
        template="""# Event summary from datamodels containing {0}:""",
        parameters=[
            "container:data.summary.threat_match_value"
        ])
    content_formatted_string = phantom.format(
        container=container,
        template="""{0}\n""",
        parameters=[
            "playbook_datamodel_events_enrichment_from_es_1:playbook_output:task_note_datamodel_summary_nodata"
        ])

    data_summary_threat_match_value_value = container.get("data", {}).get("summary", {}).get("threat_match_value", None)
    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    playbook_datamodel_events_enrichment_from_es_1_output_task_note_datamodel_summary_nodata = phantom.collect2(container=container, datapath=["playbook_datamodel_events_enrichment_from_es_1:playbook_output:task_note_datamodel_summary_nodata"])
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_4' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for playbook_datamodel_events_enrichment_from_es_1_output_task_note_datamodel_summary_nodata_item in playbook_datamodel_events_enrichment_from_es_1_output_task_note_datamodel_summary_nodata:
            for get_task_1_result_item in get_task_1_result_data:
                for get_phase_1_result_item in get_phase_1_result_data:
                    if get_incident_1_result_item[0] is not None and title_formatted_string is not None and content_formatted_string is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                        parameters.append({
                            "id": get_incident_1_result_item[0],
                            "title": title_formatted_string,
                            "content": content_formatted_string,
                            "task_id": get_task_1_result_item[0],
                            "phase_id": get_phase_1_result_item[0],
                            "response_plan_id": get_incident_1_result_item[1],
                            "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_4", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_datamodel_events_enrichment_from_es_1:playbook_output:task_note_datamodel_summary", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_task_note_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_datamodel_events_enrichment_from_es_1:playbook_output:task_note_datamodel_summary_nodata", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        add_task_note_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_task_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_task_note_5() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    get_incident_1_result_data = phantom.collect2(container=container, datapath=["get_incident_1:action_result.data.*.id","get_incident_1:action_result.data.*.current_response_plan_phase.response_plan_id","get_incident_1:action_result.parameter.context.artifact_id","get_incident_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    playbook_trustar_enrichment_1_output_note_title = phantom.collect2(container=container, datapath=["playbook_trustar_enrichment_1:playbook_output:note_title"])
    playbook_trustar_enrichment_1_output_note_content = phantom.collect2(container=container, datapath=["playbook_trustar_enrichment_1:playbook_output:note_content"])
    get_task_1_result_data = phantom.collect2(container=container, datapath=["get_task_1:action_result.data.*.id","get_task_1:action_result.parameter.context.artifact_id","get_task_1:action_result.parameter.context.artifact_external_id"], action_results=results)
    get_phase_1_result_data = phantom.collect2(container=container, datapath=["get_phase_1:action_result.data.*.id","get_phase_1:action_result.parameter.context.artifact_id","get_phase_1:action_result.parameter.context.artifact_external_id"], action_results=results)

    parameters = []

    # build parameters list for 'add_task_note_5' call
    for get_incident_1_result_item in get_incident_1_result_data:
        for playbook_trustar_enrichment_1_output_note_title_item in playbook_trustar_enrichment_1_output_note_title:
            for playbook_trustar_enrichment_1_output_note_content_item in playbook_trustar_enrichment_1_output_note_content:
                for get_task_1_result_item in get_task_1_result_data:
                    for get_phase_1_result_item in get_phase_1_result_data:
                        if get_incident_1_result_item[0] is not None and playbook_trustar_enrichment_1_output_note_title_item[0] is not None and playbook_trustar_enrichment_1_output_note_content_item[0] is not None and get_task_1_result_item[0] is not None and get_phase_1_result_item[0] is not None and get_incident_1_result_item[1] is not None:
                            parameters.append({
                                "id": get_incident_1_result_item[0],
                                "title": playbook_trustar_enrichment_1_output_note_title_item[0],
                                "content": playbook_trustar_enrichment_1_output_note_content_item[0],
                                "task_id": get_task_1_result_item[0],
                                "phase_id": get_phase_1_result_item[0],
                                "response_plan_id": get_incident_1_result_item[1],
                                "context": {'artifact_id': get_incident_1_result_item[2], 'artifact_external_id': get_incident_1_result_item[3]},
                            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("add task note", parameters=parameters, name="add_task_note_5", assets=["builtin_mc_connector"])

    return


@phantom.playbook_block()
def playbook_trustar_enrichment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_trustar_enrichment_1() called")

    data_summary_threat_match_value_value = container.get("data", {}).get("summary", {}).get("threat_match_value", None)

    inputs = {
        "ip": data_summary_threat_match_value_value,
        "domain": [],
        "url": [],
        "hash": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/trustar enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/trustar enrichment", container=container, name="playbook_trustar_enrichment_1", callback=add_task_note_5, inputs=inputs)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return