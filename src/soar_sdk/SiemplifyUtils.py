# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import calendar
import copy
import datetime
import functools
import json
import logging
import os
import re
import sys
from functools import reduce
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import arrow
import chardet
import pytz
import requests
from dateutil import parser, tz
from dateutil.tz import tzoffset
from six import string_types

if TYPE_CHECKING:
    from collections.abc import Callable

if sys.version_info >= (3, 7):
    from io import StringIO  # for handling unicode strings
    from urllib.parse import urlparse

    unicode = str
else:
    from cStringIO import StringIO
    from urlparse import urlparse

real_stdout = sys.stdout
my_stdout = StringIO()

SCRIPT_LOG_FILE: str = "script.log"
EMAIL_REGEX: str = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
DOMAIN_REGEX: str = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
ENCODING_UTF_8: str = "utf-8"
MAXIMUM_PROPERTY_VALUE: int = 3_000_000


class SessionCreator:
    @staticmethod
    def create_session() -> requests.Session:
        """Creates and return a new `requests` session.

        Returns:
            A `requests.Session` object

        """
        return requests.Session()


def set_proxy_state(
    proxy_settings: dict[str, Any],
    is_enabled: bool = True,
) -> None:
    """Set proxy state
    :proxy_settings: {dict} The proxy settings (address, username, password etc)
    :param is_enabled: {boolean} is proxy enabled
    """
    server_url = None

    if proxy_settings["proxy_server_address"]:
        server_url = urlparse(proxy_settings["proxy_server_address"])

    if proxy_settings and server_url:
        username = proxy_settings["username"]
        password = proxy_settings["password"]

        scheme = server_url.scheme
        hostname = server_url.hostname
        port = server_url.port
        ignore_addresses = ",".join(proxy_settings["ignore_addresses"])

        credentials = ""
        if username and password:
            credentials = f"{username}:{quote(password)}@"

        proxy_str = f"{scheme}://{credentials}{hostname}"

        if port:
            proxy_str += f":{port!s}"

        os.environ["http_proxy"] = proxy_str  # http://<user>:<pass>@<proxy>:<port>
        os.environ["https_proxy"] = proxy_str  # https://<user>:<pass>@<proxy>:<port>
        os.environ["no_proxy"] = ignore_addresses  # commna seperated domains etenstions

        if is_enabled:
            os.environ["proxy"] = "on"
        else:
            os.environ["proxy"] = "off"


def output_handler(func: Callable[[Any], Any]) -> Callable[[Any], Any]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception:
            sys.stderr.write("STDOUT:\n")
            sys.stderr.write(my_stdout.getvalue())
            sys.stderr.write("STDERR:\n")
            raise

    return wrapper


def override_stdout() -> None:
    sys.stdout = my_stdout


def resume_stdout() -> None:
    sys.stdout = real_stdout


def create_logger() -> logging.Logger:
    """Create logger"""
    logger = logging.getLogger("simple_example")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.NullHandler())
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    # logger.addHandler(ch)
    fh = logging.FileHandler(SCRIPT_LOG_FILE, delay=True)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)


def enrich_entities(siemplify: Any, enrichment_data: dict[str, Any]) -> None:
    """Enrich entities
    :param siemplify: {Siemplify instance}
    :param enrichment_data: {dict}
    """
    target_entities_dict = {}
    entities_to_enrich = []
    for entity in siemplify.target_entities:
        target_entities_dict[entity.identifier] = entity

    for entityIdentifier in enrichment_data:
        entity = target_entities_dict[entityIdentifier]
        entity.additional_properties.update(enrichment_data[entityIdentifier])
        entities_to_enrich.append(entity)
    siemplify.update_entities(entities_to_enrich)


def from_unix_time(unix_ms: int) -> datetime.datetime:
    """Returns the time in local time, but without stated TZ. Consider using
    convert_unixtime_to_datetime, for calculations.
    :param unix_ms: {unix time}
    :return: {datetime} time in local time
    """
    return datetime.datetime.fromtimestamp(unix_ms / 1000)


def convert_unixtime_to_datetime(unix_time: int) -> datetime.datetime:
    """Returns the time in local time with stated TZ
    :param unix_time: {unix time}
    :return: {datetime}
    """
    try:
        epoch_time = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=tz.gettz("UTC"))
        dif = datetime.timedelta(milliseconds=unix_time)
        epoch_time = epoch_time + dif
        return epoch_time
    except Exception as e:
        raise Exception(
            "{0}: {1}".format("convert_unixtime_to_datetime Failed", str(e)),
        )


def convert_datetime_to_unix_time(dt: datetime.datetime) -> int:
    """Returns the time in unix time
    :param dt: {datetime}
    :return: {unix time}
    """
    try:
        utc_date_time = dt.astimezone(tzoffset(None, 0))
        epoch_time = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=tz.gettz("UTC"))
        dif = utc_date_time - epoch_time
        total_seconds = dif.total_seconds()
        total_ms = int(total_seconds * 1000)
        return total_ms
    except Exception as e:
        raise Exception(
            "{0}: {1}".format("convert_datetime_to_unix_time Failed", str(e)),
        )


def convert_string_to_datetime(
    datetime_str: str,
    timezone_str: str | None = None,
) -> datetime.datetime:
    """Returns time in datetime format
    :param datetime_str: {string} "Tue, 28 Mar 2017 21:34:39 +0700"
    :param timezone_str: {string} ("UTC", etc)
    :return: {datetime}
    """
    try:
        dt = parser.parse(datetime_str)

        if not dt.tzinfo:
            if timezone_str:
                aware_dt = arrow.get(dt).replace(tzinfo=timezone_str)
                dt = aware_dt.datetime
            else:
                raise Exception(
                    "no timezone info was supplied (either in input string or optional parameter",
                )

        return dt
    except Exception as e:
        raise Exception("{0}: {1}".format("convert_string_to_datetime Failed", str(e)))


def convert_string_to_unix_time(datetime_str: str | None = None) -> int:
    """Return time in unix time format
    :param datetime_str: {string} "Tue, 28 Mar 2017 21:34:39 +0700"
    :return: {unix time}
    """
    try:
        dt = convert_string_to_datetime(datetime_str)
        return convert_datetime_to_unix_time(dt)
    except Exception as e:
        raise Exception("{0}: {1}".format("convert_string_to_unix_time Failed", str(e)))


def utc_now() -> datetime.datetime:
    """Get utc current time
    :return: {datetime}
    """
    return datetime.datetime.now(tz=tz.gettz("UTC"))


def unix_now() -> int:
    """Get utc current time ad unix time
    :return: {long} unix time
    """
    new_timestamp = convert_datetime_to_unix_time(utc_now())
    return new_timestamp


def utc_to_local(utc_dt: datetime.datetime) -> datetime.datetime:
    """Return local time (without stated TZ)
    :param utc_dt: {datetime} (with stated TZ - UTC)
    :return: {datetime}
    """
    # get integer timestamp to avoid precision lost
    timestamp = calendar.timegm(utc_dt.timetuple())
    local_dt = datetime.datetime.fromtimestamp(timestamp)
    assert utc_dt.resolution >= datetime.timedelta(microseconds=1)
    return local_dt.replace(microsecond=utc_dt.microsecond)


# https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
def convert_timezone(
    source_aware_datetime: datetime.datetime,
    destination_timezone_str: str,
) -> datetime.datetime:
    """Stated TZ to datetime object.
    :param source_aware_datetime: {datetime}
    :param destination_timezone_str: {string} timezone (e.g. Africa/Abidjan)
    :return: {datetime} converted datetime
    """
    arrow_dt_source = arrow.get(source_aware_datetime)
    arrow_dt_dest = arrow_dt_source.to(tz=destination_timezone_str)
    converted_dt = arrow_dt_dest.datetime
    return converted_dt


def set_utc_timezone_to_naive_datetime(
    naive_datetime: datetime.datetime,
) -> datetime.datetime:
    """Convert naive datetime to aware datetime
    :param naive_datetime: {datetime} without stated TZ
    :return: {datetime} aware datetime
    """
    time_zone = pytz.timezone("UTC")
    # is_dst = _is_dst_in_effect(time_zone)
    return time_zone.localize(dt=naive_datetime)


def add_prefix_to_dict(
    given_dict: dict[str, Any],
    prefix: str,
) -> dict[str, Any]:
    """Add prefix to the given dict keys
    :param given_dict: {dict}
    :param prefix: {string} prefix to be added to the given dict
    :return: {dict}
    """
    return {f"{prefix}_{key}": value for key, value in list(given_dict.items())}


def extract_domain(email: str) -> str:
    """Get domain dfrom email address
    :param email: {string} email address (user@domain.com)
    :return: {string} domain (domain.com)
    """
    return email.split("@")[-1]


def get_email_address(entity: Any) -> str | None:
    """Get email address
    :param entity: {entity}
    :return: email address if found, else None.
    """
    try:
        if "Email" in entity.additional_properties:
            return entity.additional_properties["Email"]
        if re.match(EMAIL_REGEX, entity.identifier, re.IGNORECASE):
            return entity.identifier
    except:
        pass
    return None


def get_domain(entity: Any) -> str | None:
    """Get domain
    :param entity: {entity}
    :return: domain if found, else None.
    """
    try:
        if "Email" in entity.additional_properties:
            return extract_domain(entity.additional_properties["Email"])
        if re.match(DOMAIN_REGEX, entity.identifier):
            return extract_domain(entity.identifier)
    except:
        pass
    return None


def add_prefix_to_dict_encoded_keys(
    target_dict: dict[str, Any],
    prefix: str,
    encoding: str = ENCODING_UTF_8,
    error_handling: str = "strict",
) -> dict[str, Any]:
    """Add prefix to the given dict keys.
    In Python2 assuming keys are either 'unicode' or 'str' with the
    appropriate encoding and prefix is 'unicode' or ASCII 'str'.
    In Python3 assuming keys and prefix are 'str'.
    In both cases, if the input is of type bytes we decode it using the 'encoding'
    :param target_dict: {dict}
    :param prefix: {string} prefix to be added to the given dict
    :param encoding: What encoding to try. default UTF-8
    :param error_handling: What type of error handling. Default 'strict'.
    optional values: [strict, ignore, replace, backslashreplace, surrogateescape,
    xmlcharrefreplace, namereplace, surrogatepass]
    See https://docs.python.org/3/library/codecs.html#error-handlers for more details
    :return: Result Dictionary {dict}. In Python2, keys are of type 'unicode'. In
    Python3 keys are of class 'str'.
    """
    result_dict = {}
    for key, val in target_dict.items():
        if is_python_37():  # str represents unicode in python3 and thus we decode any bytes array
            if isinstance(key, bytes):
                key = key.decode(encoding, errors=error_handling)
            new_key = f"{prefix}_{key}"
        else:  # str represents binary data and thus needs encoding into unicode
            if isinstance(key, str) or isinstance(key, bytes):
                key = key.decode(
                    encoding=ENCODING_UTF_8,
                    errors=error_handling,
                )  # Key is now unicode
            new_key = f"{prefix}_{key}"  # Implicitly converting prefix to unicode as well

        result_dict[new_key] = val

    return result_dict


def add_prefix_to_dict_keys(
    target_dict: dict[str, Any],
    prefix: str,
) -> dict[str, Any]:
    """Add prefix to the given dict keys
    :param target_dict: {dict}
    :param prefix: {string} prefix to be added to the given dict
    :return: add_prefix_to_dict_encoded_keys() {dict}
    We changed this method and redirected it to a fixed method since
    this it worked correctly only for python2 causing unit tests to fail.
    """
    return add_prefix_to_dict_encoded_keys(target_dict, prefix)


def is_dict_in_list(target_list: list[Any]) -> dict[Any, Any] | None:
    """Check if dict is in list
    :param target_list: {list}
    :return: First dict at the list : {dict}
    """
    for member in target_list:
        if isinstance(member, dict):
            return member
    return None


def dict_to_flat(target_dict: dict[str, Any]) -> dict[str, Any]:
    """Receives nested dictionary and returns it as a flat dictionary.
    :param target_dict: {dict}
    :return: Flat dict : {dict}
    """
    target_dict = copy.deepcopy(target_dict)

    def expand(raw_key, raw_value):
        key = validate_string(raw_key, convert_none=True, ignore_non_str=True)
        value = validate_string(raw_value, convert_none=True, ignore_non_str=True)
        """
        :param key: {string}
        :param value: {string}
        :return: Recursive function.
        """
        if not value:
            return [(key, "")]
        if isinstance(value, dict):
            # Handle dict type value
            return [
                (
                    "{0}_{1}".format(
                        key,
                        validate_string(
                            sub_key,
                            convert_none=True,
                            ignore_non_str=True,
                        ),
                    ),
                    validate_string(sub_value, convert_none=True, ignore_non_str=True),
                )
                for sub_key, sub_value in list(dict_to_flat(value).items())
            ]
        if isinstance(value, list):
            # Handle list type value
            count = 1
            l = []
            items_to_remove = []
            for value_item in value:
                if isinstance(value_item, dict):
                    # Handle nested dict in list
                    l.extend(
                        [
                            (
                                "{0}_{1}_{2}".format(
                                    validate_string(
                                        key,
                                        convert_none=True,
                                        ignore_non_str=True,
                                    ),
                                    str(count),
                                    validate_string(
                                        sub_key,
                                        convert_none=True,
                                        ignore_non_str=True,
                                    ),
                                ),
                                sub_value,
                            )
                            for sub_key, sub_value in list(
                                dict_to_flat(value_item).items(),
                            )
                        ],
                    )
                    items_to_remove.append(value_item)
                    count += 1
                elif isinstance(value_item, list):
                    l.extend(expand(key + "_" + str(count), value_item))
                    count += 1
                    items_to_remove.append(value_item)

            for value_item in items_to_remove:
                value.remove(value_item)

            for value_item in value:
                l.extend([(key + "_" + str(count), value_item)])
                count += 1

            return l
        return [(key, value)]

    items = [
        item
        for sub_key, sub_value in list(target_dict.items())
        for item in expand(sub_key, sub_value)
    ]
    return dict(items)


def flat_dict_to_csv(flat_dict: dict[str, Any]) -> list[str]:
    """Turns flat dict to CSV format string list.
    :param flat_dict: {dict}
    :return: CSV format string list : {list}
    """
    csv_format = []
    csv_head = "Property, Value"
    csv_format.append(csv_head)
    for key, value in list(flat_dict.items()):
        safe_key = validate_string(key, convert_none=True, ignore_non_str=True)
        safe_value = validate_string(value, convert_none=True, ignore_non_str=True)
        csv_format.append(f"{safe_key},{safe_value}")
    return csv_format


def get_domain_from_entity(entity: Any) -> str | None:
    """Extract domain from entity
    :param entity: {entity}
    :return: {str} domain or None
    """
    if "@" in entity.identifier:
        return entity.identifier.split("@", 1)[-1]

    try:
        import tldextract

        result = tldextract.extract(entity.identifier)
        if result.suffix:
            return ".".join([result.domain, result.suffix])
        return result.domain
    except ImportError:
        raise ImportError("tldextract is not installed. Use pip and install it.")


def construct_csv(
    list_of_dicts: list[dict[str, Any]],
) -> list[str]:
    """Constructs a csv from list_of_dicts
    :param list_of_dicts: The list_of_dicts to add to the csv (list_of_dicts are list
    of flat dicts)
    :return: {list} csv formatted list
    """
    csv_output = []
    if not list_of_dicts:
        return csv_output

    headers = reduce(set.union, map(set, map(dict.keys, list_of_dicts)))
    unicode_headers = []
    for header in headers:
        header = adjust_to_csv(header)
        header = get_unicode(header)
        unicode_headers.append(header)
    csv_output.append(",".join(unicode_headers))

    for result in list_of_dicts:
        csv_row = []
        for header in headers:
            cell_value = result.get(header)
            cell_value = adjust_to_csv(cell_value)
            cell_value = get_unicode(cell_value)

            # Replace problematic commas
            cell_value = cell_value.replace(",", " ")
            # Append values to the row
            csv_row.append(cell_value)
        # Append row to the output
        csv_output.append(",".join(csv_row))
    return csv_output


def delete_older_files_from_folder(folder_path: str, days_to_keep: int = 1) -> None:
    """Delete files from a folder that are older than given number of days
    backwards
    :param folder_path: {str} The full path to the folder
    :param days_to_keep: {int} Number of days backward to keep files from
    """
    for dir_path, dir_names, file_names in os.walk(folder_path):
        for file_name in file_names:
            full_path = os.path.join(dir_path, file_name)
            file_modified = datetime.datetime.fromtimestamp(os.path.getmtime(full_path))
            if datetime.datetime.now() - file_modified > datetime.timedelta(
                days=days_to_keep,
            ):
                os.remove(full_path)


def validate_string(
    string: Any,
    convert_none: bool = False,
    ignore_non_str: bool = False,
) -> str:
    """Differentiate string encoding between python2 and python3
    :param string:  {Basestring}
    :return: {str}
    """
    if is_python_37():
        return validate_string_python3(string, convert_none, ignore_non_str)
    return validate_string_python2(string, convert_none, ignore_non_str)


def validate_string_python3(
    string: Any,
    convert_none: bool = False,
    ignore_non_str: bool = False,
) -> str:
    """Validates string encoding, in case of unicode the string will be encoded and
    returned as a string object
    :param string:  {Basestring}
    :return: {str}
    """
    if convert_none == True and string is None:
        return str(None)

    if isinstance(string, bytes):
        return str(string)
    if ignore_non_str:
        return string
    raise Exception(
        "validate string error: Given object in not any basestring type",
    )


def validate_string_python2(
    string: Any,
    convert_none: bool = False,
    ignore_non_str: bool = False,
) -> str:
    """Validates string encoding, in case of unicode the string will be encoded and
    returned as a string object
    :param string:  {Basestring}
    :return: {str}
    """
    if convert_none == True and string is None:
        return str(None)

    if isinstance(string, unicode):
        return string.encode(ENCODING_UTF_8)
    if isinstance(string, str) or ignore_non_str:
        return string
    raise Exception(
        "validate string error: Given object in not any basestring type",
    )


def create_entity_json_result_object(
    entity_identifier: str,
    json_result_for_entity: dict[str, Any],
) -> dict[str, Any]:
    """Organize entity json result object to set format.
    :param entity_identifier: {string} Entity identifier string.
    :param json_result_for_entity: {dict} JSON result for specific entity.
    :return: {dict} Entity JSON result object.
    """
    return {"Entity": entity_identifier, "EntityResult": json_result_for_entity}


def convert_dict_to_json_result_dict(
    json_result_dict: dict[str, Any] | str,
) -> list[dict[str, Any]]:
    """Convert key, value JSON result to JSON result object list.
    :param json_result_dict: {dict} Key, val JSON result.
    :return: {list} List of entity JSON result objects.
    """
    # In case input is string, try to load it:
    if isinstance(json_result_dict, str) or isinstance(json_result_dict, str):
        json_result_dict = json.loads(json_result_dict)

    return [
        create_entity_json_result_object(entity_identifier, entity_data)
        for entity_identifier, entity_data in list(json_result_dict.items())
    ]


def get_brother_virtualenv_directory(integration_name: str) -> str:
    """Creates and validates the path of a parallel virtual environment folder. This
    structure is coupled with server code
    :param integration_name: {str} Name of the integration
    :return: {str} Path to the virtual environment directory
    """
    current_directory_parent = os.path.dirname(os.getcwd())
    brother_virutal_env_directory = os.path.join(
        current_directory_parent,
        integration_name,
    )

    if not os.path.isdir(brother_virutal_env_directory):
        raise Exception(
            f"Couldn't find brother directory '{brother_virutal_env_directory}'",
        )

    return brother_virutal_env_directory


def link_brother_envrionment(siemplify: Any, integration_identifier: str) -> None:
    """Links the virutal envrionment folder of another integration to current process (
    Managers & pip modules)
    :param siemplify: {Siemplify} Siemplify instance
    :param integration_identifier: {str} Integration identifier
    :return: None
    """
    integration_name = (
        f"{integration_identifier}_V{siemplify.get_integration_version(integration_identifier)!s}"
    )
    brother_directory = get_brother_virtualenv_directory(integration_name)

    # fix paths
    if "win" in os.environ.get("OS", "").lower():
        modules_directory = os.path.join(brother_directory, r"Lib\site-packages")
    else:
        # linux
        site_packages_path = (
            f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
        )
        modules_directory = os.path.join(brother_directory, site_packages_path)

    sys.path.append(brother_directory)  # location of managers
    sys.path.append(modules_directory)  # location of pip installs


def extract_script_param(
    siemplify: Any,
    input_dictionary: dict[str, Any],
    param_name: str,
    default_value: Any = None,
    input_type: type = str,
    is_mandatory: bool = False,
    print_value: bool = False,
) -> Any:
    # internal param validation:
    if not siemplify:
        raise Exception("Parameter 'siemplify' cannot be None")

    if not param_name:
        raise Exception("Parameter 'param_name' cannot be None")

    if default_value and not (type(default_value) == input_type):
        raise Exception(
            f"Given default_value of '{default_value}' doesn't match expected type {input_type.__name__}",
        )

    #  =========== start validation logic =====================
    value = input_dictionary.get(param_name)

    if input_type == list:
        value = json.loads(value)

    if not value:
        if is_mandatory:
            raise Exception(f"Missing mandatory parameter {param_name}")
        value = default_value
        siemplify.LOGGER.info(
            f"Parameter {param_name} was not found or was empty, used default_value {default_value} "
            "instead",
        )

    # None values should not be converted.
    if value is None:
        return None

    if input_type == bool:
        lowered = str(value).lower()
        valid_lowered_bool_values = [
            str(True).lower(),
            str(False).lower(),
            str(bool(None)).lower(),
        ]  # In Python - None and bool False are the same logicly
        if lowered not in valid_lowered_bool_values:
            raise Exception(
                f"Parameter named {param_name}, with value {value} isn't a valid BOOL",
            )
        result = lowered == str(True).lower()
    elif input_type == int:
        result = int(value)
    elif input_type == float:
        result = float(value)
    elif input_type == str:
        result = str(value)
    elif input_type == list:
        result = list(value)
    else:
        raise Exception(
            f"input_type {input_type.__name__} isn't not supported for conversion",
        )

    if print_value:
        siemplify.LOGGER.info(f"{param_name}: {result}")

    return result


def extract_environment(
    envrioment_field_name: str | None,
    default_envrioment_value: Any,
    data: dict[str, Any],
) -> Any:
    if envrioment_field_name:
        return data.get(envrioment_field_name)
    return default_envrioment_value


def get_unicode(value: Any) -> str:
    if is_python_37():
        return get_unicode_python3(value)
    return get_unicode_python2(value)


def decode_bytes(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        try:
            encoding = chardet.detect(value).get("encoding")
            value = value.decode(encoding)
        except Exception:
            value = "Unable to decode value (unknown encoding)"
    return value


def get_unicode_python3(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return decode_bytes(value)
    try:
        return str(value)
    except Exception:
        return "Unable to get text representation of object"


def get_unicode_python2(value: Any) -> str:
    if isinstance(value, unicode):
        return value
    if not isinstance(value, basestring):
        # Validate that the cell is a basestring. If not convert it to string
        try:
            value = str(value)
        except Exception:
            value = "Unable to get text representation of object"
    if value is None:
        # If the value is empty, leave the cell empty
        value = ""
    if isinstance(value, str):
        value = decode_bytes(value)
    return value


def adjust_to_csv(value: str | None) -> str:
    if value is None:
        return ""
    return value


def is_python_37() -> bool:
    return sys.version_info >= (3, 7)


def is_at_least_python_3_11() -> bool:
    return sys.version_info >= (3, 11)


def is_old_entities_format(entities: list[Any]) -> bool:
    if entities and all(isinstance(e, string_types) for e in entities):
        return True
    return False


def is_json_result_size_valid(result_json: str, max_size_in_mb: int) -> bool:
    # check if string len is greater than max size after conversion to bytes
    if len(result_json) > max_size_in_mb * 1_048_576:
        return False
    return True


def validate_property_value(property_value: str) -> bool:
    if len(str(property_value)) > MAXIMUM_PROPERTY_VALUE:
        return False
    return True


def is_unixtimestamp_valid(timestamp_unix_ms: int) -> bool:
    try:
        datetime.datetime.fromtimestamp(timestamp_unix_ms // 1_000)
        return True
    except Exception:
        return False


def is_str_instance(value: Any) -> bool:
    """Returns true if the value is a str instance
    Support python2.7 and python 3.7+
    """
    if is_python_37():
        return isinstance(value, str)
    return isinstance(value, basestring)
