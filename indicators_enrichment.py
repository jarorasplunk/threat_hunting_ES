"""
Use Intelligence Management to gather threat information about indicators in a SOAR event. Tag the indicators with the normalized priority score from Intelligence Management and summarize the findings in an analyst note. This playbook is meant to be used as a child playbook executed by a parent playbook such as &quot;threat_intel_investigate&quot;.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_2' block
    filter_2(container=container)

    return

@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["playbook_input:indicator_type", "!=", ""],
            ["playbook_input:indicators", "!=", ""]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:playbook_input:indicator_type", "==", "ip"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        vt_ip_reputation(action=action, success=success, container=container, results=results, handle=handle)
        umbrella_investigate_indicator_report(action=action, success=success, container=container, results=results, handle=handle)
        crowdstrike_ip_indicator(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:playbook_input:indicator_type", "==", "domain"]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        return

    # check for 'elif' condition 3
    found_match_3 = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_2:condition_1:playbook_input:indicator_type", "==", "url"]
        ],
        delimiter=None)

    # call connected blocks if condition 3 matched
    if found_match_3:
        return

    return


@phantom.playbook_block()
def vt_ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vt_ip_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_indicators = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:playbook_input:indicators"])

    parameters = []

    # build parameters list for 'vt_ip_reputation' call
    for filtered_input_0_indicators_item in filtered_input_0_indicators:
        if filtered_input_0_indicators_item[0] is not None:
            parameters.append({
                "ip": filtered_input_0_indicators_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="vt_ip_reputation", assets=["virustotal test"], callback=vt_indicator_found)

    return


@phantom.playbook_block()
def umbrella_investigate_indicator_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("umbrella_investigate_indicator_report() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_indicators = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:playbook_input:indicators"])

    parameters = []

    # build parameters list for 'umbrella_investigate_indicator_report' call
    for filtered_input_0_indicators_item in filtered_input_0_indicators:
        if filtered_input_0_indicators_item[0] is not None:
            parameters.append({
                "ip": filtered_input_0_indicators_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="umbrella_investigate_indicator_report", assets=["cisco umbrella investigate"], callback=decision_2)

    return


@phantom.playbook_block()
def crowdstrike_ip_indicator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("crowdstrike_ip_indicator() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    resource_id_formatted_string = phantom.format(
        container=container,
        template="""ip_address_{0}\n""",
        parameters=[
            "filtered-data:filter_2:condition_1:playbook_input:indicators"
        ])

    filtered_input_0_indicators = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:playbook_input:indicators"])

    parameters = []

    # build parameters list for 'crowdstrike_ip_indicator' call
    for filtered_input_0_indicators_item in filtered_input_0_indicators:
        parameters.append({
            "resource_id": resource_id_formatted_string,
            "indicator_value": "",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get indicator", parameters=parameters, name="crowdstrike_ip_indicator", assets=["crowdstrike splunk soar connector"], callback=decision_3)

    return


@phantom.playbook_block()
def vt_indicator_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vt_indicator_found() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["vt_ip_reputation:action_result.summary.harmless", ">", 0],
            ["vt_ip_reputation:action_result.summary.malicious", ">", 0],
            ["vt_ip_reputation:action_result.summary.suspicious", ">", 0]
        ],
        name="vt_indicator_found:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        vt_indicator_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def vt_indicator_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vt_indicator_report() called")

    vt_ip_reputation_result_data = phantom.collect2(container=container, datapath=["vt_ip_reputation:action_result.data.*.id","vt_ip_reputation:action_result.data.*.attributes.as_owner","vt_ip_reputation:action_result.data.*.attributes.asn","vt_ip_reputation:action_result.data.*.attributes.country","vt_ip_reputation:action_result.data.*.attributes.network","vt_ip_reputation:action_result.data.*.attributes.reputation","vt_ip_reputation:action_result.summary.harmless","vt_ip_reputation:action_result.summary.malicious","vt_ip_reputation:action_result.summary.suspicious","vt_ip_reputation:action_result.summary.undetected","vt_ip_reputation:action_result.data.*.links.self"], action_results=results)

    vt_ip_reputation_result_item_0 = [item[0] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_result_item_1 = [item[1] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_result_item_2 = [item[2] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_result_item_3 = [item[3] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_result_item_4 = [item[4] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_result_item_5 = [item[5] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_summary_harmless = [item[6] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_summary_malicious = [item[7] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_summary_suspicious = [item[8] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_summary_undetected = [item[9] for item in vt_ip_reputation_result_data]
    vt_ip_reputation_result_item_10 = [item[10] for item in vt_ip_reputation_result_data]

    input_parameter_0 = ""
    input_parameter_1 = ""

    vt_indicator_report__vt_note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import urllib.parse
    
    if vt_ip_reputation_result_item_0:
        note = (
            "\n**Virustotal report**\n"
            "| Indicator | AS_Owner | ASN | Country | Network | Reputation | Harmless | Malicious | Suspicious | Undetected | Full Report |\n"
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
        )
        for item in vt_ip_reputation_result_data:
                indicator = item[0]
                as_owner = item[1]
                asn = item[2]
                country = item[3]
                network = item[4]
                reputation = item[5]
                harmless = item[6]
                malicious = item[7]
                suspicious = item[8]
                undetected = item[9]
                full_report = item[10]
                note += "|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|\n".format(indicator, as_owner, asn, country, network, reputation, harmless, malicious, suspicious, undetected, full_report)
        vt_indicator_report__vt_note_content = note
    else:
        vt_indicator_report__vt_note_content = "\n\n**Virustotal report**\n\nIndicator not found in Virustotal\n"    
    
    phantom.debug("vt_indicator_report__vt_note_content")    
    phantom.debug(vt_indicator_report__vt_note_content)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="vt_indicator_report:vt_note_content", value=json.dumps(vt_indicator_report__vt_note_content))

    join_noop_2(container=container)

    return


@phantom.playbook_block()
def umbrella_indicator_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("umbrella_indicator_report() called")

    umbrella_investigate_indicator_report_result_data = phantom.collect2(container=container, datapath=["umbrella_investigate_indicator_report:action_result.parameter.ip","umbrella_investigate_indicator_report:action_result.summary.ip_status","umbrella_investigate_indicator_report:action_result.summary.total_blocked_domains","umbrella_investigate_indicator_report:action_result.data.*.id","umbrella_investigate_indicator_report:action_result.data.*.name","umbrella_investigate_indicator_report:action_result.status"], action_results=results)

    umbrella_investigate_indicator_report_parameter_ip = [item[0] for item in umbrella_investigate_indicator_report_result_data]
    umbrella_investigate_indicator_report_summary_ip_status = [item[1] for item in umbrella_investigate_indicator_report_result_data]
    umbrella_investigate_indicator_report_summary_total_blocked_domains = [item[2] for item in umbrella_investigate_indicator_report_result_data]
    umbrella_investigate_indicator_report_result_item_3 = [item[3] for item in umbrella_investigate_indicator_report_result_data]
    umbrella_investigate_indicator_report_result_item_4 = [item[4] for item in umbrella_investigate_indicator_report_result_data]
    umbrella_investigate_indicator_report_result_item_5 = [item[5] for item in umbrella_investigate_indicator_report_result_data]

    umbrella_indicator_report__umbrella_note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import urllib.parse        
    
    if umbrella_investigate_indicator_report_result_item_5 != "failed":
        note = (
            "\n\n**Cisco Umbrella Investigate report**\n"
            "| Indicator | Status | Number of blocked domains | Blocked domain ID | Blocked domain name |\n"
            "| :--- | :--- | :--- | :--- | :--- |\n"
        )
        limit = 25
        phantom.debug(type(limit))
        if umbrella_investigate_indicator_report_summary_total_blocked_domains[0]:
            blocked_count = int(umbrella_investigate_indicator_report_summary_total_blocked_domains[0])
        else:
            blocked_count = 0
        phantom.debug(type(blocked_count))
        phantom.debug(blocked_count)
        
        if blocked_count >= limit:
            for item in umbrella_investigate_indicator_report_result_data[0:24]:
                indicator = item[0]
                ip_status = item[1]
                no_blocked_domains = item[2]
                blocked_domain_id = item[3]
                blocked_domain_name = item[4]
                note += "|{}|{}|{}|{}|{}|\n".format(indicator, ip_status, no_blocked_domains, blocked_domain_id, blocked_domain_name)
            note += "\nOnly 25 out of total " + str(blocked_count) + " blocked domains displayed here. For complete list of blocked domains, please check in Cisco Umbrella Investigate or in the Automation tab\n" 
        else:                
            for item in umbrella_investigate_indicator_report_result_data:
                indicator = item[0]
                ip_status = item[1]
                no_blocked_domains = item[2]
                blocked_domain_id = item[3]
                blocked_domain_name = item[4]
                note += "|{}|{}|{}|{}|{}|\n".format(indicator, ip_status, no_blocked_domains, blocked_domain_id, blocked_domain_name)
    
    if umbrella_investigate_indicator_report_result_item_5 == "failed":
        note = "\n\n**Cisco Umbrella Investigate report**\n\nIndicator not found in Cisco Umbrella Investigate\n"
        
    umbrella_indicator_report__umbrella_note_content = note
    phantom.debug("umbrella_indicator_report__umbrella_note_content")    
    phantom.debug(umbrella_indicator_report__umbrella_note_content)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="umbrella_indicator_report:umbrella_note_content", value=json.dumps(umbrella_indicator_report__umbrella_note_content))

    join_noop_2(container=container)

    return


@phantom.playbook_block()
def crowdstrike_indicator_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("crowdstrike_indicator_report() called")

    crowdstrike_ip_indicator_result_data = phantom.collect2(container=container, datapath=["crowdstrike_ip_indicator:action_result.parameter.resource_id","crowdstrike_ip_indicator:action_result.status","crowdstrike_ip_indicator:action_result.summary","crowdstrike_ip_indicator:action_result.message"], action_results=results)

    crowdstrike_ip_indicator_parameter_resource_id = [item[0] for item in crowdstrike_ip_indicator_result_data]
    crowdstrike_ip_indicator_result_item_1 = [item[1] for item in crowdstrike_ip_indicator_result_data]
    crowdstrike_ip_indicator_result_item_2 = [item[2] for item in crowdstrike_ip_indicator_result_data]
    crowdstrike_ip_indicator_result_message = [item[3] for item in crowdstrike_ip_indicator_result_data]

    crowdstrike_indicator_report__crowdstrike_note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import urllib.parse
    if crowdstrike_ip_indicator_result_message != "Indicator not found":
        note = (
            "\n\n**Crowdstrike report**\n"
            "| Indicator | Status | Summary | Message |\n"
            "| :--- | :--- | :--- | :--- |\n"
        )
    
        for item in crowdstrike_ip_indicator_result_data:
            indicator = item[0]
            status = item[1]
            summary = item[2]
            message = item[3]
            note += "|{}|{}|{}|{}|\n".format(indicator, status, summary, message)
        if note is not None:
            crowdstrike_indicator_report__crowdstrike_note_content = note
            
    if crowdstrike_ip_indicator_result_message == "Indicator not found":
        crowdstrike_indicator_report__crowdstrike_note_content = "\n\n**Crowdstrike report**\n\nIndicator not found in Crowdstrike\n"
    
    phantom.debug("crowdstrike_indicator_report__crowdstrike_note_content")    
    phantom.debug(crowdstrike_indicator_report__crowdstrike_note_content)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="crowdstrike_indicator_report:crowdstrike_note_content", value=json.dumps(crowdstrike_indicator_report__crowdstrike_note_content))

    join_noop_2(container=container)

    return


@phantom.playbook_block()
def full_report_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("full_report_note() called")

    umbrella_indicator_report__umbrella_note_content = json.loads(_ if (_ := phantom.get_run_data(key="umbrella_indicator_report:umbrella_note_content")) != "" else "null")  # pylint: disable=used-before-assignment
    crowdstrike_indicator_report__crowdstrike_note_content = json.loads(_ if (_ := phantom.get_run_data(key="crowdstrike_indicator_report:crowdstrike_note_content")) != "" else "null")  # pylint: disable=used-before-assignment
    vt_indicator_report__vt_note_content = json.loads(_ if (_ := phantom.get_run_data(key="vt_indicator_report:vt_note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    full_report_note__full_report_note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    import urllib.parse
    
    #vt_indicator_report__vt_note_content = json.loads(phantom.get_run_data(key="vt_indicator_report:vt_note_content"))# pylint: disable=used-before-assignment
    #umbrella_indicator_report__umbrella_note_content = json.loads(phantom.get_run_data(key="umbrella_indicator_report:umbrella_note_content")) # pylint: disable=used-before-assignment
    #crowdstrike_indicator_report__crowdstrike_note_content = json.loads(phantom.get_run_data(key="crowdstrike_indicator_report:crowdstrike_note_content")) # pylint: disable=used-before-assignment
    
    phantom.debug("Full report - vt_indicator_report__vt_note_content")
    phantom.debug(vt_indicator_report__vt_note_content)
    phantom.debug("Full report - umbrella_indicator_report__umbrella_note_content")
    phantom.debug(umbrella_indicator_report__umbrella_note_content)
    phantom.debug("Full report - crowdstrike_indicator_report__crowdstrike_note_content")
    phantom.debug(crowdstrike_indicator_report__crowdstrike_note_content)
    
    if vt_indicator_report__vt_note_content is None:
        vt_indicator_report__vt_note_content = "\n**Virustotal report**\n\nIndicator not found in Virustotal\n"
    if umbrella_indicator_report__umbrella_note_content is None:
        umbrella_indicator_report__umbrella_note_content = "\n**Cisco Umbrella Investigate report**\n\nIndicator not found in Cisco Umbrella Investigate\n"
    if crowdstrike_indicator_report__crowdstrike_note_content is None:
        crowdstrike_indicator_report__crowdstrike_note_content = "\n**Crowdstrike report**\n\nIndicator not found in Crowdstrike\n"
        
    note = vt_indicator_report__vt_note_content
    note += umbrella_indicator_report__umbrella_note_content
    note += crowdstrike_indicator_report__crowdstrike_note_content
    full_report_note__full_report_note_content = note
    # Write your custom code here...
    
    phantom.debug("full_report_note__full_report_note_content")
    phantom.debug(full_report_note__full_report_note_content)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="full_report_note:full_report_note_content", value=json.dumps(full_report_note__full_report_note_content))

    return


@phantom.playbook_block()
def join_noop_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_noop_2() called")

    if phantom.completed(action_names=["vt_ip_reputation", "umbrella_investigate_indicator_report", "crowdstrike_ip_indicator"]):
        # call connected block "noop_2"
        noop_2(container=container, handle=handle)

    return


@phantom.playbook_block()
def noop_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("noop_2() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/noop", parameters=parameters, name="noop_2", callback=full_report_note)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["umbrella_investigate_indicator_report:action_result.status", "!=", None]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        umbrella_indicator_report(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["crowdstrike_ip_indicator:action_result.message", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        crowdstrike_indicator_report(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    full_report_note__full_report_note_content = json.loads(_ if (_ := phantom.get_run_data(key="full_report_note:full_report_note_content")) != "" else "null")  # pylint: disable=used-before-assignment

    note_title_combined_value = phantom.concatenate("Indicator Enrichment Report", dedup=True)
    note_content_combined_value = phantom.concatenate(full_report_note__full_report_note_content, dedup=True)

    output = {
        "note_title": note_title_combined_value,
        "note_content": note_content_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return