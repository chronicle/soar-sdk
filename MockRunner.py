import json
from base64 import b64encode

from dateutil.tz import tz

# from SiemplifyMock import SiemplifyMock
from SiemplifyMock import SiemplifyActionMock
from SiemplifyDataModel import Task
import SiemplifyUtils
import datetime
import pytz
import sys
import os


def test_time_converters(siemplify):
    utcNow = SiemplifyUtils.utc_now()
    unixNow = SiemplifyUtils.unix_now()
    convertedUtcNow = SiemplifyUtils.convert_datetime_to_unix_time(utcNow)
    convertedString = SiemplifyUtils.convert_string_to_unix_time("Tue, 28 Mar 2017 21:34:39 +0700")

    israelTime = datetime.datetime(1993, 2, 23, 14, 23, 20, tzinfo=tz.gettz("Israel"))

    conv1 = SiemplifyUtils.convert_datetime_to_unix_time(israelTime)
    conv2 = SiemplifyUtils.convert_unixtime_to_datetime(conv1)
    conv3 = SiemplifyUtils.convert_datetime_to_unix_time(conv2)
    conv4 = SiemplifyUtils.convert_unixtime_to_datetime(conv3)
    local = SiemplifyUtils.utc_to_local(israelTime)
    legacyConvert = SiemplifyUtils.from_unix_time(conv3)


def test_timestamps(siemplify):
    lastRunTime = siemplify.fetch_timestamp()
    siemplify.save_timestamp(True)
    lastRunTime = siemplify.fetch_and_save_timestamp(True, "Israel")
    print(lastRunTime)

    lastRunTime = siemplify.fetch_timestamp(True)
    print(lastRunTime)

    lastRunTime = siemplify.fetch_timestamp(True, "Israel")
    print(lastRunTime)

    lastRunTime = siemplify.fetch_timestamp()
    print(lastRunTime)

    lastRunTime = siemplify.fetch_and_save_timestamp()
    print(lastRunTime)

    lastRunTime = siemplify.fetch_and_save_timestamp(True, "Israel")
    print(lastRunTime)

    lastRunTime = siemplify.fetch_and_save_timestamp(True)
    print(lastRunTime)

    lastRunTime = siemplify.fetch_and_save_timestamp(True, "Israel")
    print(lastRunTime)

    lastRunTime = siemplify.fetch_and_save_timestamp()
    print(lastRunTime)

    lastRunTime = siemplify.fetch_and_save_timestamp()
    print(lastRunTime)


def test_timestamps2(siemplify):
    dtA = datetime.datetime(1990, 10, 5, 15, 40, tzinfo=pytz.timezone("UTC"))
    siemplify.save_timestamp(new_timestamp=dtA)
    lastRunTimeA1 = siemplify.fetch_timestamp()
    lastRunTimeA2 = siemplify.fetch_timestamp(True)
    # lastRunTimeA3 = siemplify.fetch_timestamp(True, "Israel")

    # dtB = datetime.datetime(1990, 10, 5, 2, 40, tzinfo=pytz.timezone("Israel"))
    # siemplify.save_timestamp(new_timestamp=dtB)
    lastRunTimeB1 = siemplify.fetch_timestamp()
    lastRunTimeB2 = siemplify.fetch_timestamp(True)
    # lastRunTimeB3 = siemplify.fetch_timestamp(True, "Israel")

    dtCA = 655094400000
    siemplify.save_timestamp(new_timestamp=dtA)
    lastRunTimeC1 = siemplify.fetch_timestamp()
    lastRunTimeC2 = siemplify.fetch_timestamp(True)
    # lastRunTimeC3 = siemplify.fetch_timestamp(True, "Israel")

    idt = pytz.timezone("Israel")
    utc = pytz.timezone("utc")

    dtC = dtA.astimezone(pytz.timezone("Israel"))

    naive_datetime = datetime.datetime(1990, 10, 8, 5, 40)
    idt_dt = idt.localize(naive_datetime, is_dst=False)
    utc_dt = idt_dt.astimezone(utc)

    dtT1 = SiemplifyUtils.set_utc_timezone_to_naive_datetime(datetime.datetime(1990, 10, 8, hour=10, minute=30))
    dtT2 = SiemplifyUtils.set_utc_timezone_to_naive_datetime(
        datetime.datetime(1990, 10, 8, hour=10, minute=30, microsecond=2000))
    # dtT3 = SiemplifyUtils.set_timezone_to_naive_datetime(datetime.datetime(1990,10,8,hour=10, minute=30),timezone_str="Israel")
    # dtT4 = SiemplifyUtils.set_timezone_to_naive_datetime(datetime.datetime(1990,10,8, hour=10, minute=30,microsecond=2000),timezone_str="Australia/Melbourne")

    x = datetime.datetime(datetime.datetime.now().year, 1, 1, 0, 0, 0, tzinfo=idt)  # Jan 1 of this year
    y = datetime.datetime.now(idt)
    is_dst = (y.utcoffset() == x.utcoffset())

    now = datetime.datetime.now()
    x = datetime.datetime(now.year, 1, 1, 0, 0, 0, tzinfo=pytz.utc)  # Jan 1 of this year
    y = datetime.datetime.now(pytz.utc)

    # if DST is in effect, their offsets will be different
    return not (y.utcoffset() == x.utcoffset())


def test_timestamp_string_conversions(siemplify):
    str_input_israel_dst_true = "25/3/1990 14:30:00 +0300"
    str_input_israel_dst_false = "23/3/1990 14:30:00 +0200"

    str_input_naive_1 = "25/3/1990 14:30:00"
    str_input_naive_2 = "23/3/1990 14:30:00"
    str_input_naive_2 = "20/3/1990 14:30:00"

    israel_dst_true = SiemplifyUtils.convert_string_to_datetime(str_input_israel_dst_true)
    israel_dst_false = SiemplifyUtils.convert_string_to_datetime(str_input_israel_dst_false)
    # naive_dt1 = SiemplifyUtils.convert_string_to_datetime(str_input_naive_1) ---- Raises exceptions
    # naive_dt1 = SiemplifyUtils.convert_string_to_datetime(str_input_naive_2) ---- Raises exceptions
    israel_from_aware_dst_true = SiemplifyUtils.convert_string_to_datetime(str_input_naive_1, "Asia/Jerusalem")
    israel_from_aware_dst_false = SiemplifyUtils.convert_string_to_datetime(str_input_naive_2, "Asia/Jerusalem")


def test_timestamp_timezone_conversions(siemplify):
    str_input_naive_1 = "3/27/1990 14:30:00"  # Israel dst, usPacific dst
    str_input_naive_2 = "3/24/1990 14:30:00"  # usPacific dst
    str_input_naive_3 = "3/8/1990 14:30:00"  # no dst

    israel_1 = SiemplifyUtils.convert_string_to_datetime(str_input_naive_1, "Asia/Jerusalem")  # +3
    israel_2 = SiemplifyUtils.convert_string_to_datetime(str_input_naive_2, "Asia/Jerusalem")  # +2
    israel_3 = SiemplifyUtils.convert_string_to_datetime(str_input_naive_3, "Asia/Jerusalem")  # +2

    unix1 = SiemplifyUtils.convert_datetime_to_unix_time(israel_1)
    unix2 = SiemplifyUtils.convert_datetime_to_unix_time(israel_2)
    unix3 = SiemplifyUtils.convert_datetime_to_unix_time(israel_3)

    utc_1 = SiemplifyUtils.convert_timezone(israel_1, "UTC")  # 11:30 +0
    utc_2 = SiemplifyUtils.convert_timezone(israel_2, "UTC")  # 12:30 +0
    utc_3 = SiemplifyUtils.convert_timezone(israel_3, "UTC")  # 12:30 +0
    us_pacific_1 = SiemplifyUtils.convert_timezone(israel_1, "America/Los_Angeles")  # -7 04:30
    us_pacific_2 = SiemplifyUtils.convert_timezone(israel_2, "America/Los_Angeles")  # -7 05:30
    us_pacific_3 = SiemplifyUtils.convert_timezone(israel_3, "America/Los_Angeles")  # -8 04:30

    us_pacific_1A = SiemplifyUtils.convert_string_to_datetime(str_input_naive_1, "Europe/Skopje")  # -7 14:30
    us_pacific_2A = SiemplifyUtils.convert_string_to_datetime(str_input_naive_2, "Europe/Skopje")  # -7 14:30
    us_pacific_3A = SiemplifyUtils.convert_string_to_datetime(str_input_naive_3, "Europe/Skopje")  # -8 14:30


def permitted_test(siemplify):
    unix_dst_off_0930 = 1518593400000
    unix_dst_on_0930 = 1526365800000
    unix_dst_off_1030 = 1518597000000
    unix_dst_on_1030 = 1526369400000

    dt_zone_dst_off_0930 = SiemplifyUtils.convert_unixtime_to_datetime(1518593400000)
    dt_zone_dst_on_0930 = SiemplifyUtils.convert_unixtime_to_datetime(1526365800000)
    dt_zone_dst_off_1030 = SiemplifyUtils.convert_unixtime_to_datetime(1518597000000)
    dt_zone_dst_on_1030 = SiemplifyUtils.convert_unixtime_to_datetime(1526369400000)

    dt1_zone_dst_off_0930 = dt_zone_dst_off_0930.astimezone(pytz.timezone("Israel")).time()
    dt1_zone_dst_on_0930 = dt_zone_dst_on_0930.astimezone(pytz.timezone("Israel")).time()
    dt1_zone_dst_off_1030 = dt_zone_dst_off_1030.astimezone(pytz.timezone("Israel")).time()
    dt1_zone_dst_on_1030 = dt_zone_dst_on_1030.astimezone(pytz.timezone("Israel")).time()

    dt2_zone_dst_off_0930 = SiemplifyUtils.convert_timezone(dt_zone_dst_off_0930, "Israel").time()
    dt2_zone_dst_on_0930 = SiemplifyUtils.convert_timezone(dt_zone_dst_on_0930, "Israel").time()
    dt2_zone_dst_off_1030 = SiemplifyUtils.convert_timezone(dt_zone_dst_off_1030, "Israel").time()
    dt2_zone_dst_on_1030 = SiemplifyUtils.convert_timezone(dt_zone_dst_on_1030, "Israel").time()


def close_case_test(siemplify):
    root_cause = "Example Root Cause"
    comment = "Example close Comment"
    reason = "Malicious"
    siemplify.close_case(root_cause, comment, reason)


def file_retention_test(siemplify):
    from FileRetentionManager import FileRetentionManager
    import os
    frm = FileRetentionManager(siemplify.LOGGER)
    root = "C:\FILE RETENTION TEST"
    done = os.path.join(root, "DONE")
    frm.retensify_file("C:\FILE RETENTION TEST\A.txt", done, 3)
    print("retensifed")


def change_case_priority(siemplify, priority):
    siemplify.LOGGER.info("case priority is: {0}".format(siemplify.case.priority))
    temp_priority = siemplify.case.priority

    siemplify.change_case_priority(priority)

    siemplify.load_case_data()
    siemplify.LOGGER.info("case priority changed to: {0}".format(siemplify.case.priority))

    siemplify.change_case_priority(temp_priority)
    siemplify.load_case_data()
    siemplify.LOGGER.info("case priority is: {0} again".format(siemplify.case.priority))


def change_case_stage(siemplify, stage):
    siemplify.LOGGER.info("case stage is: {0}".format(siemplify.case.stage))
    temp_stage = siemplify.case.stage

    siemplify.change_case_stage(stage)

    siemplify.load_case_data()
    siemplify.LOGGER.info("case stage changed to: {0}".format(siemplify.case.stage))

    siemplify.change_case_stage(temp_stage)
    siemplify.load_case_data()
    siemplify.LOGGER.info("case stage is: {0} again".format(siemplify.case.stage))


def test_alert_entities_custom_list(siemplify):
    alert_in_test = siemplify.any_alert_entities_in_custom_list("python_tester")
    siemplify.LOGGER.info("alert entities in custom list python_tester: {0}".format(alert_in_test))

    siemplify.LOGGER.info("add alert entities to custom list python_tester")
    siemplify.add_alert_entities_to_custom_list("python_tester")

    alert_in_test = siemplify.any_alert_entities_in_custom_list("python_tester")
    siemplify.LOGGER.info("alert entities was added to list python_tester: {0}".format(alert_in_test))

    siemplify.LOGGER.info("remove alert entities from custom list python_tester")
    siemplify.remove_alert_entities_from_custom_list("python_tester")

    alert_in_test = siemplify.any_alert_entities_in_custom_list("python_tester")
    siemplify.LOGGER.info("alert entities was removed from list python_tester: {0}".format(not alert_in_test))


def test_extract_action_param(siemplify):
    test_str = siemplify.extract_action_param("test_str")
    print(test_str)
    test_empty = siemplify.extract_action_param("test_empty", "Empty")
    print(test_empty)
    test_int = siemplify.extract_action_param("test_int", 0, int)
    print(test_int)
    test_bool = siemplify.extract_action_param("test_bool", True, bool)
    print(test_bool)


def test_result_object(siemplify):
    dummy_json = build_large_dummy_json(1)
    for entity in siemplify.target_entities:
        if SiemplifyUtils.is_python_37():
            B64 = b64encode(b"Dummy Content").decode()
        else:
            B64 = b64encode(b"Dummy Content")
        siemplify.result.add_entity_attachment(entity.identifier, "Attachment for: {0}".format(entity.identifier), B64)
        siemplify.result.add_entity_html_report(entity.identifier, "HTML for: {0}".format(entity.identifier),
                                                "<html><body><div>{0}</div></body>></html>".format(entity.identifier))
        siemplify.result.add_content(entity.identifier, "Content for: {0}".format(entity.identifier))
        siemplify.result.add_entity_link(entity.identifier, "https://wwww.google.com")
        siemplify.result.add_entity_json(entity.identifier, json.dumps(dummy_json))
        siemplify.result.add_entity_table(entity.identifier, SiemplifyUtils.flat_dict_to_csv(dummy_json))
        siemplify.result.add_result_json(dummy_json)


def test_action_functions(siemplify):
    """
    change_case_priority(siemplify, 40)
    change_case_stage(siemplify, "Triage")

    siemplify.LOGGER.info("add new case comment")
    siemplify.add_comment("pythonTester - {0}".format(sys.version_info.major))

    siemplify.LOGGER.info("add new case tag")
    siemplify.add_tag("pythonTester - {0}".format(sys.version_info.major))

    if len(siemplify.target_entities) is not 0:
        siemplify.LOGGER.info("add entity insight")
        siemplify.add_entity_insight(siemplify.target_entities[0], "pythonTester - {0}".format(sys.version_info.major))
    else:
        siemplify.LOGGER.info("case has no entities")

    test_alert_entities_custom_list(siemplify)
    publisher = siemplify.get_publisher_by_id(1)
    siemplify.add_attachment("C:/FILE RETENTION TEST/file.txt")
    for entity in siemplify.target_entities:


    attachments = siemplify.get_attachments()
    comments = siemplify.get_case_comments()
    alerts = siemplify.get_alerts_ticket_ids_from_cases_closed_since_timestamp(1540409785000, 'Phishing email detector')
    configuration = siemplify.get_configuration('Siemplify')
    siemplify.raise_incident()
    siemplify.mark_case_as_important()
    siemplify.attach_workflow_to_case("test_workflow")
    test_extract_action_param(siemplify)

    # siemplify.escalate_case("@Tier2") # 404 - function not implemented
    siemplify.close_alert("Lab test", "Test SDK", 2)
    siemplify.close_case("Lab test", "Test SDK", 2)
    """

    siemplify.end('output message', 'true')


def test_task_function(siemplify):
    if SiemplifyUtils.is_python_37():
        now = datetime.datetime.now().timestamp()
    else:
        now = (datetime.datetime.now() - datetime.datetime(1970, 1, 1)).total_seconds()

    case_tasks = siemplify.get_case_tasks(siemplify.case_id)
    task_id = siemplify.add_or_update_case_task(Task(siemplify.case_id, "Test SDK", siemplify.original_requesting_user))
    siemplify.add_or_update_case_task(Task(siemplify.case_id, "Test SDK", siemplify.original_requesting_user,
                                           status=1, completion_comment="Test Done", completion_date_time=now,
                                           id=task_id))
    case_tasks = siemplify.get_case_tasks(siemplify.case_id)


def test_entities_update_function(siemplify):
    for entity in siemplify.target_entities:
        entity.additional_properties['EnrichmentProperty'] = "Test SDK"

    siemplify.update_entities(siemplify.target_entities)
    siemplify.load_case_data()

    for entity in siemplify.target_entities:
        entity.additional_properties['EnrichmentProperty'] = None

    siemplify.update_entities(siemplify.target_entities)
    siemplify.load_case_data()


def test_alerts_update_data_function(siemplify):
    siemplify.update_alerts_additional_data({
        "EnrichmentProperty": "Test SDK"
    })


def test_sdk_functions(siemplify):
    # test_task_function(siemplify)
    # siemplify.check_marketpalce_status()
    # siemplify.send_system_notification("This is a test of the python sdk")
    # category_exist = siemplify.is_existing_category("python_tester")
    # custom_list_categories = siemplify.get_existing_custom_list_categories()

    priorities_cases = siemplify.get_cases_by_filter(start_time_unix_time_in_ms=100213863400, end_time_unix_time_in_ms=1572208634000)
    cases_by_ticket_id_1 = siemplify.get_cases_by_ticket_id(1)

    # test_entities_update_function(siemplify)

    # case_closure_details = siemplify.get_case_closure_details([siemplify.case_id])
    # test_alert_entities_custom_list(siemplify)
    test_alerts_update_data_function(siemplify)


def test_logger_functions(siemplify):
    siemplify.LOGGER.info("--Message Test---", module="module1", file_name="C:\\File.txt", alert_id="123456",
                          miliseconds=34)
    siemplify.LOGGER.warn("--Message Test---", module="module1", file_name="C:\\File.txt", alert_id="123456",
                          miliseconds=34)

    siemplify.LOGGER.error("--Message Test---", module="module1", file_name="C:\\File.txt", alert_id="123456",
                           miliseconds=34)

    try:
        dict_1 = {"a": 0}
        c = dict_1["b"]
    except Exception as e:
        siemplify.LOGGER.exception(e, module="module1", file_name="C:\\File.txt", alert_id="123456", miliseconds=34)


def test_utils_functions(siemplify):
    SiemplifyUtils.link_brother_envrionment(siemplify, "SiemplifyTest27")


def build_large_dummy_json(records_amount):
    result_json = {}
    for i in range(records_amount):
        record = "aaaaaaaaaa {0} bbbbbbbbbbbbb"
        result_json[record.format(i)] = record.format(i)
    return result_json


def main():
    siemplify = SiemplifyActionMock()
    siemplify.script_name = 'MockRunner'

    siemplify.LOGGER.info(siemplify.run_folder)
    siemplify.LOGGER.info("------------Started----------")

    # Put your test here (please don't checkin changes to main test method)
    response = siemplify.get_similar_cases(True, True, True, True, days_to_look_back=3)
    # a = siemplify._current_alert
    # Please check out the log examples:
    test_logger_functions(siemplify)

    # test_sdk_functions(siemplify)
    # test_utils_functions(siemplify)
    # test_action_functions(siemplify)

    siemplify.LOGGER.info("------------Finished----------")


if __name__ == "__main__":
    main()
