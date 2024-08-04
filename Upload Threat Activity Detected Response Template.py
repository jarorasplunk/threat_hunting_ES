"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'create_response_templates' block
    create_response_templates(container=container)

    return

@phantom.playbook_block()
def create_response_templates(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_response_templates() called")

    create_response_templates__threat_activity_investigation_json_body = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    var_true = True
    var_false = False
    var_0 = 0
    var_1 = 1
    var_2 = 2
    var_3 = 3
    
    # Create JSON body for "Risk Notable Investigation" response plan
    
    create_response_templates__threat_activity_investigation_json_body = {
        "name": "Threat Activity Detected from IP address",
        "version": "1",
        "is_default": var_false,
        "description": "A series of tasks for enrichment, investigation and response to incidents created by Threat Activity Detected incidents",
        "template_status": "published",
        "phases": [
            {
                "name": "Gather related events and threat context",
                "order": var_1,
                "tasks": [
                    {
                        "name": "[AUTO] Gather related events from Network, Web and Authentication datamodels",
                        "order": var_1,
                        "description": "This playbook will run queries across Network, Web and Authentication datamodels to get any other related events showing communication with the threat IP address",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": [
                                {
                                    "name": "Threat_Activity_Detected_IP_investigation",
                                    "scope": "all",
                                    "description": "This master playbook will call individual input playbooks to create summary for the incident",
                                    "playbook_id": "local/Threat_Activity_Detected_IP_investigation",
                                    "last_job_id": var_0
                                }
                            ]
                        },
                        "is_note_required": var_false
                    },
                    {
                        "name": "[MANUAL] Vet indicator based on analysis and submit to Trustar",
                        "order": var_2,
                        "description": "This task provides the capability to submit validated IOC to Trustar with additional flags for blacklisting",
                        "suggestions": {
                            "actions": "submit report - TruSTAR",
                            "searches": [],
                            "playbooks": [],
                        },
                        "is_note_required": var_false
                    },
                    {
                        "name": "[MANUAL] Remediation actions",
                        "order": var_3,
                        "description": "Containment actions as required by the analysts based on the threat hunting information gathered in previous tasks",
                        "suggestions": {
                            "actions": [],
                            "searches": [],
                            "playbooks": []
                        },
                        "is_note_required": var_false
                    }
                ]
            }
        ]
       }
            
                  
    
    convert_json_threat_activity_investigation = json.dumps(create_response_templates__threat_activity_investigation_json_body)
    phantom.debug(convert_json_threat_activity_investigation)
    create_response_templates__threat_activity_investigation_json_body = convert_json_threat_activity_investigation 
    
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="create_response_templates:threat_activity_investigation_json_body", value=json.dumps(create_response_templates__threat_activity_investigation_json_body))

    upload_risk_notable_investigate_plan(container=container)
    upload_risk_notable_response_plan(container=container)
    upload_risk_notable_auto_response_plan(container=container)

    return


@phantom.playbook_block()
def upload_risk_notable_investigate_plan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upload_risk_notable_investigate_plan() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_response_templates__risk_investigation_json_body = json.loads(_ if (_ := phantom.get_run_data(key="create_response_templates:risk_investigation_json_body")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "body": create_response_templates__risk_investigation_json_body,
        "location": "servicesNS/-/missioncontrol/v1/responsetemplates",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="upload_risk_notable_investigate_plan", assets=["mission_control"], callback=join_noop_1)

    return


@phantom.playbook_block()
def upload_risk_notable_response_plan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upload_risk_notable_response_plan() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_response_templates__risk_response_json_body = json.loads(_ if (_ := phantom.get_run_data(key="create_response_templates:risk_response_json_body")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "body": create_response_templates__risk_response_json_body,
        "location": "servicesNS/-/missioncontrol/v1/responsetemplates",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="upload_risk_notable_response_plan", assets=["mission_control"], callback=join_noop_1)

    return


@phantom.playbook_block()
def upload_risk_notable_auto_response_plan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("upload_risk_notable_auto_response_plan() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    create_response_templates__risk_auto_response_json_body = json.loads(_ if (_ := phantom.get_run_data(key="create_response_templates:risk_auto_response_json_body")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "body": create_response_templates__risk_auto_response_json_body,
        "location": "servicesNS/-/missioncontrol/v1/responsetemplates",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="upload_risk_notable_auto_response_plan", assets=["mission_control"], callback=join_noop_1)

    return


@phantom.playbook_block()
def join_noop_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_noop_1() called")

    if phantom.completed(action_names=["upload_risk_notable_investigate_plan", "upload_risk_notable_response_plan", "upload_risk_notable_auto_response_plan"]):
        # call connected block "noop_1"
        noop_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def noop_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("noop_1() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/noop", parameters=parameters, name="noop_1")

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