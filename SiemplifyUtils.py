import sys
import copy
import logging
import calendar
import os
import re
import arrow
import json
from six import string_types
from six.moves.urllib.parse import quote

# Date Time Converter:
import datetime
from dateutil import parser
from dateutil import tz
import pytz
from dateutil.tz import tzoffset
from functools import reduce

if sys.version_info >= (3, 7):
    from io import StringIO    # for handling unicode strings
    from urllib.parse import urlparse
    unicode = str
else:
    from cStringIO import StringIO
    from urlparse import urlparse

real_stdout = sys.stdout
my_stdout = StringIO()

# CONSTS
SCRIPT_LOG_FILE = "script.log"
EMAIL_REGEX = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
DOMAIN_REGEX = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
ENCODING_UTF_8 = "utf-8"
MAXIMUM_PROPERTY_VALUE = 3000000


def set_proxy_state(proxy_settings, is_enabled=True):
    """
    Set proxy state
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
            credentials = "{0}:{1}@".format(username, quote(password))

        proxy_str = "{0}://{1}{2}".format(scheme, credentials, hostname)

        if port:
            proxy_str += ":{0}".format(str(port))

        os.environ['http_proxy'] = proxy_str  # http://<user>:<pass>@<proxy>:<port>
        os.environ['https_proxy'] = proxy_str  # https://<user>:<pass>@<proxy>:<port>
        os.environ['no_proxy'] = ignore_addresses  # commna seperated domains etenstions

        if is_enabled:
            os.environ['proxy'] = "on"
        else:
            os.environ['proxy'] = "off"


def output_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            sys.stderr.write("STDOUT:\n")
            sys.stderr.write(my_stdout.getvalue())
            sys.stderr.write("STDERR:\n")
            raise

    return wrapper


def override_stdout():
    sys.stdout = my_stdout


def resume_stdout():
    sys.stdout = real_stdout


def create_logger():
    """
    create logger
    """
    logger = logging.getLogger('simple_example')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.NullHandler())
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    # logger.addHandler(ch)
    fh = logging.FileHandler(SCRIPT_LOG_FILE, delay=True)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)


# logger.addHandler(fh)


def enrich_entities(siemplify, enrichment_data):
    """
    enrich entities
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


def from_unix_time(unix_ms):
    """
    returns the time in local time, but without stated TZ. Consider using convert_unixtime_to_datetime, for calculations.
    :param unix_ms: {unix time}
    :return: {datetime} time in local time
    """
    return datetime.datetime.fromtimestamp(unix_ms / 1000)


def convert_unixtime_to_datetime(unix_time):
    """
    returns the time in local time with stated TZ
    :param unix_time: {unix time}
    :return: {datetime}
    """
    try:
        epoch_time = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=tz.gettz("UTC"))
        dif = datetime.timedelta(milliseconds=unix_time)
        epoch_time = epoch_time + dif
        return epoch_time
    except Exception as e:
        raise Exception("{0}: {1}".format("convert_unixtime_to_datetime Failed", str(e)))


def convert_datetime_to_unix_time(dt):
    """
    returns the time in unix time
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
        raise Exception("{0}: {1}".format("convert_datetime_to_unix_time Failed", str(e)))


def convert_string_to_datetime(datetime_str, timezone_str=None):
    """
    returns time in datetime format
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
                raise Exception("no timezone info was supplied (either in input string or optional parameter")

        return dt
    except Exception as e:
        raise Exception("{0}: {1}".format("convert_string_to_datetime Failed", str(e)))


def convert_string_to_unix_time(datetime_str=None):
    """
    return time in unix time format
    :param datetime_str: {string} "Tue, 28 Mar 2017 21:34:39 +0700"
    :return: {unix time}
    """
    try:
        dt = convert_string_to_datetime(datetime_str)
        return convert_datetime_to_unix_time(dt)
    except Exception as e:
        raise Exception("{0}: {1}".format("convert_string_to_unix_time Failed", str(e)))


def utc_now():
    """
    get utc current time
    :return: {datetime}
    """
    return datetime.datetime.now(tz=tz.gettz("UTC"))


def unix_now():
    """
    get utc current time ad unix time
    :return: {long} unix time
    """
    new_timestamp = convert_datetime_to_unix_time(utc_now())
    return new_timestamp


def utc_to_local(utc_dt):
    """
    return local time (without stated TZ)
    :param utc_dt: {datetime} (with stated TZ - UTC)
    :return: {datetime}
    """
    # get integer timestamp to avoid precision lost
    timestamp = calendar.timegm(utc_dt.timetuple())
    local_dt = datetime.datetime.fromtimestamp(timestamp)
    assert utc_dt.resolution >= datetime.timedelta(microseconds=1)
    return local_dt.replace(microsecond=utc_dt.microsecond)


# https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
def convert_timezone(source_aware_datetime, destination_timezone_str):
    """
    stated TZ to datetime object.
    :param source_aware_datetime: {datetime}
    :param destination_timezone_str: {string} timezone (e.g. Africa/Abidjan)
    :return: {datetime} converted datetime
    """
    arrow_dt_source = arrow.get(source_aware_datetime)
    arrow_dt_dest = arrow_dt_source.to(tz=destination_timezone_str)
    converted_dt = arrow_dt_dest.datetime
    return converted_dt


def set_utc_timezone_to_naive_datetime(naive_datetime):
    """
    convert naive datetime to aware datetime
    :param naive_datetime: {datetime} without stated TZ
    :return: {datetime} aware datetime
    """
    time_zone = pytz.timezone("UTC")
    # is_dst = _is_dst_in_effect(time_zone)
    return time_zone.localize(dt=naive_datetime)


# Untested. Also, missing reverse method (with normalize etc'?)
# def _is_dst_in_effect(pytz_timezone):
#    """Determine whether or not Daylight Savings Time (DST)
#       is currently in effect"""
#    now = datetime.datetime.now()
#    x = datetime.datetime(now.year, 1, 1, 0, 0, 0, tzinfo=pytz_timezone)  # Jan 1 of this year
#    y = datetime.datetime.now(pytz_timezone)
#
#    # if DST is in effect, their offsets will be different
#    return not (y.utcoffset() == x.utcoffset())

def add_prefix_to_dict(given_dict, prefix):
    """
    add prefix to the given dict keys
    :param given_dict: {dict}
    :param prefix: {string} prefix to be added to the given dict
    :return: {dict}
    """
    return {'{0}_{1}'.format(prefix, key): value for key, value in list(given_dict.items())}


def extract_domain(email):
    """
    get domain dfrom email address
    :param email: {string} email address (user@domain.com)
    :return: {string} domain (domain.com)
    """
    return email.split("@")[-1]


def get_email_address(entity):
    """
    get email address
    :param entity: {entity}
    :return: email address if found, else None.
    """
    try:
        if "Email" in entity.additional_properties:
            return entity.additional_properties["Email"]
        else:
            if re.match(EMAIL_REGEX, entity.identifier, re.IGNORECASE):
                return entity.identifier
    except:
        pass
    return


def get_domain(entity):
    """
    get domain
    :param entity: {entity}
    :return: domain if found, else None.
    """
    try:
        if "Email" in entity.additional_properties:
            return extract_domain(entity.additional_properties["Email"])
        else:
            if re.match(DOMAIN_REGEX, entity.identifier):
                return extract_domain(entity.identifier)
    except:
        pass
    return

def add_prefix_to_dict_encoded_keys(target_dict, prefix, encoding=ENCODING_UTF_8, error_handling='strict'):
    """
    add prefix to the given dict keys. 
    In Python2 assuming keys are either 'unicode' or 'str' with the 
    appropriate encoding and prefix is 'unicode' or ASCII 'str'. 
    In Python3 assuming keys and prefix are 'str'.
    In both cases, if the input is of type bytes we decode it using the 'encoding'
    :param target_dict: {dict}
    :param prefix: {string} prefix to be added to the given dict
    :param encoding: What encoding to try. default UTF-8
    :param error_handling: What type of error handling. Default 'strict'.
    optional values: [strict, ignore, replace, backslashreplace, surrogateescape, xmlcharrefreplace, namereplace, surrogatepass]
    See https://docs.python.org/3/library/codecs.html#error-handlers for more details
    :return: Result Dictionary {dict}. In Python2, keys are of type 'unicode'. In Python3 keys are of class 'str'.
    """
    result_dict = {}
    for key, val in target_dict.items():
        if is_python_37():  # str represents unicode in python3 and thus we decode any bytes array
            if isinstance(key, bytes):
                key = key.decode(encoding, errors=error_handling)
            new_key = "{0}_{1}".format(prefix, key)
        else:  # str represents binary data and thus needs encoding into unicode
            if isinstance(key, str) or isinstance(key, bytes):
                key = key.decode(encoding=ENCODING_UTF_8, errors=error_handling) # Key is now unicode
            new_key = u"{0}_{1}".format(prefix, key)  # Implicitly converting prefix to unicode as well
        
        result_dict[new_key] = val

    return result_dict

def add_prefix_to_dict_keys(target_dict, prefix):
    """
    add prefix to the given dict keys
    :param target_dict: {dict}
    :param prefix: {string} prefix to be added to the given dict
    :return: Result Dictionary {dict}
    """
    result_dict = {}
    for key, val in target_dict.items():
        key = key.encode(ENCODING_UTF_8) if isinstance(key, str) else key
        new_key = "{0}_{1}".format(prefix, str(key))
        result_dict[new_key] = val

    return result_dict


def is_dict_in_list(target_list):
    """
    check if dict is in list
    :param target_list: {list}
    :return: First dict at the list : {dict}
    """
    for member in target_list:
        if isinstance(member, dict):
            return member
    return


def dict_to_flat(target_dict):
    """
    Receives nested dictionary and returns it as a flat dictionary.
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
        elif isinstance(value, dict):
            # Handle dict type value
            return [("{0}_{1}".format(key,
                                      validate_string(sub_key, convert_none=True, ignore_non_str=True)),
                     validate_string(sub_value, convert_none=True, ignore_non_str=True)) for sub_key, sub_value in list(dict_to_flat(value).items())]
        elif isinstance(value, list):
            # Handle list type value
            count = 1
            l = []
            items_to_remove = []
            for value_item in value:
                if isinstance(value_item, dict):
                    # Handle nested dict in list
                    l.extend([("{0}_{1}_{2}".format(validate_string(key, convert_none=True, ignore_non_str=True),
                                                    str(count),
                                                    validate_string(sub_key, convert_none=True, ignore_non_str=True)),
                               sub_value)
                              for sub_key, sub_value in list(dict_to_flat(value_item).items())])
                    items_to_remove.append(value_item)
                    count += 1
                elif isinstance(value_item, list):
                    l.extend(expand(key + '_' + str(count), value_item))
                    count += 1
                    items_to_remove.append(value_item)

            for value_item in items_to_remove:
                value.remove(value_item)

            for value_item in value:
                l.extend([(key + '_' + str(count), value_item)])
                count += 1

            return l
        else:
            return [(key, value)]

    items = [item for sub_key, sub_value in list(target_dict.items()) for item in
             expand(sub_key, sub_value)]
    return dict(items)


def flat_dict_to_csv(flat_dict):
    """
    Turns flat dict to CSV format string list.
    :param flat_dict: {dict}
    :return: CSV format string list : {list}
    """
    csv_format = []
    csv_head = "Property, Value"
    csv_format.append(csv_head)
    for key, value in list(flat_dict.items()):
        safe_key = validate_string(key, convert_none=True, ignore_non_str=True)
        safe_value = validate_string(value, convert_none=True, ignore_non_str=True)
        csv_format.append("{0},{1}".format(safe_key, safe_value))
    return csv_format


def get_domain_from_entity(entity):
    """
    extract domain from entity
    :param entity: {entity}
    :return:
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


def construct_csv(list_of_dicts):
    """
    Constructs a csv from list_of_dicts
    :param list_of_dicts: The list_of_dicts to add to the csv (list_of_dicts are list of flat dicts)
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
    csv_output.append(u",".join(unicode_headers))

    for result in list_of_dicts:
        csv_row = []
        for header in headers:
            cell_value = result.get(header)
            cell_value = adjust_to_csv(cell_value)
            cell_value = get_unicode(cell_value)

            # Replace problematic commas
            cell_value = cell_value.replace(u',', u' ')
            # Append values to the row
            csv_row.append(cell_value)
        # Append row to the output
        csv_output.append(u",".join(csv_row))
    return csv_output


def delete_older_files_from_folder(folder_path, days_to_keep=1):
    """
    Delete files from a folder that are older than given number of days
    backwards
    :param folder_path: {str} The full path to the folder
    :param days_to_keep: {int} Number of days backward to keep files from
    """
    for dir_path, dir_names, file_names in os.walk(folder_path):
        for file_name in file_names:
            full_path = os.path.join(dir_path, file_name)
            file_modified = datetime.datetime.fromtimestamp(
                os.path.getmtime(full_path))
            if datetime.datetime.now() - file_modified > datetime.timedelta(
                    days=days_to_keep):
                os.remove(full_path)


def validate_string(string, convert_none = False, ignore_non_str = False):
    """
    Differentiate string encoding between python2 and python3
    :param string:  {Basestring}
    :return: {str}
    """
    if is_python_37():
        return validate_string_python3(string, convert_none, ignore_non_str)
    else:
        return validate_string_python2(string, convert_none, ignore_non_str)

def validate_string_python3(string, convert_none = False, ignore_non_str = False):
    """
    Validates string encoding, in case of unicode the string will be encoded and returned as a string object
    :param string:  {Basestring}
    :return: {str}
    """


    if convert_none==True and string is None:
        return str(None)

    if isinstance(string, bytes):
        return str(string)
    elif ignore_non_str:
        return string
    else:
        raise Exception("validate string error: Given object in not any basestring type")


def validate_string_python2(string, convert_none = False, ignore_non_str = False):
    """
    Validates string encoding, in case of unicode the string will be encoded and returned as a string object
    :param string:  {Basestring}
    :return: {str}
    """


    if convert_none==True and string is None:
        return str(None)

    if isinstance(string, unicode):
        return string.encode(ENCODING_UTF_8)
    elif isinstance(string, str):
        return string
    elif ignore_non_str:
        return string
    else:
        raise Exception("validate string error: Given object in not any basestring type")


def create_entity_json_result_object(entity_identifier, json_result_for_entity):
    """
    Organize entity json result object to set format.
    :param entity_identifier: {string} Entity identifier string.
    :param json_result_for_entity: {dict} JSON result for specific entity.
    :return: {dict} Entity JSON result object.
    """
    return {"Entity": entity_identifier, "EntityResult": json_result_for_entity}


def convert_dict_to_json_result_dict(json_result_dict):
    """
    Convert key, value JSON result to JSON result object list.
    :param json_result_dict: {dict} Key, val JSON result.
    :return: {list} List of entity JSON result objects.
    """
    #In case input is string, try to load it:
    if isinstance(json_result_dict, str) or isinstance(json_result_dict, str):
        json_result_dict = json.loads(json_result_dict)

    return [create_entity_json_result_object(entity_identifier, entity_data) for entity_identifier, entity_data
            in list(json_result_dict.items())]


def get_brother_virtualenv_directory(integration_name):
    """
    Creates and validates the path of a parallel virtual environment folder. This structure is coupled with server code
    :param integration_name:
    :return:
    """
    current_directory_parent = os.path.dirname(os.getcwd())
    brother_virutal_env_directory = os.path.join(current_directory_parent, integration_name)

    if not os.path.isdir(brother_virutal_env_directory):
        raise Exception("Couldn't find brother directory '{0}'".format(brother_virutal_env_directory))

    return brother_virutal_env_directory


def link_brother_envrionment(siemplify, integration_identifier):
    """
    links the virutal envrionment folder of another integration to current process (Managers & pip modules)
    :param integration_identifier:
    :return:
    """
    integration_name = "{0}_V{1}".format(integration_identifier, str(siemplify.get_integration_version(integration_identifier)))
    brother_directory = get_brother_virtualenv_directory(integration_name)

    # fix paths
    if 'win' in os.environ.get('OS', '').lower():
        modules_directory = os.path.join(brother_directory, "Lib\site-packages")
    else:
        # linux
        site_packages_path = "lib/python{0}.{1}/site-packages".format(sys.version_info.major,sys.version_info.minor)
        modules_directory = os.path.join(brother_directory, site_packages_path)

    sys.path.append(brother_directory)  # location of managers
    sys.path.append(modules_directory)  # location of pip installs

def extract_script_param(siemplify, input_dictionary, param_name, default_value=None, input_type=str, is_mandatory=False, print_value=False):
    # internal param validation:
    if not siemplify:
        raise Exception("Parameter 'siemplify' cannot be None")

    if not param_name:
        raise Exception("Parameter 'param_name' cannot be None")

    if default_value and not (type(default_value) == input_type):
        raise Exception("Given default_value of '{0}' doesn't match expected type {1}".format(default_value, input_type.__name__))

    #  =========== start validation logic =====================
    value = input_dictionary.get(param_name)
    
    if input_type == list:
        value = json.loads(value)
    
    if not value:
        if is_mandatory:
            raise Exception("Missing mandatory parameter {0}".format(param_name))
        else:
            value = default_value
            siemplify.LOGGER.info("Parameter {0} was not found or was empty, used default_value {1} instead".format(param_name, default_value))

    # None values should not be converted.
    if value is None:
        return None

    if input_type == bool:
        lowered = str(value).lower()
        valid_lowered_bool_values = [str(True).lower(), str(False).lower(), str(bool(None)).lower()] # In Python - None and bool False are the same logicly
        if lowered not in valid_lowered_bool_values:
            raise Exception("Parameter named {0}, with value {1} isn't a valid BOOL".format(param_name, value))
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
        raise Exception("input_type {0} isn't not supported for conversion".format(input_type.__name__))

    if print_value:
        siemplify.LOGGER.info("{}: {}".format(param_name, result))

    return result


def extract_environment(envrioment_field_name, default_envrioment_value, data):
    if envrioment_field_name:
        return data.get(envrioment_field_name)
    else:
        return default_envrioment_value

def get_unicode(value):
    if isinstance(value, unicode):
        return value
    if not isinstance(value, basestring):
        # Validate that the cell is a basestring. If not convert it to string
        try:
            value = str(value)
        except Exception:
            value = u"Unable to get text representation of object"
    if value is None:
        # If the value is empty, leave the cell empty
        value = u""
    if isinstance(value, str):
        try:
            value = value.decode("utf8")
        except UnicodeDecodeError:
            try:
                encoding = chardet.detect(value).get('encoding')
                value = value.decode(encoding)
            except Exception:
                value = u"Unable to decode value (unknown encoding)"
    return value
    
def adjust_to_csv(value):
    if value is None:
        return ""
    return value


def is_python_37():
    return sys.version_info >= (3, 7)
    
    
def is_old_entities_format(entities):
    if entities and all(isinstance(e, string_types) for e in entities) :
        return True
    else:
        return False
        
def is_json_result_size_valid(result_json, max_size_in_mb):
    #check if string len is greater than max size after conversion to bytes
    if len(result_json) > max_size_in_mb * 1048576: 
        return False
    return True
    
    
def validate_property_value(property_value):
    if len(str(property_value)) > MAXIMUM_PROPERTY_VALUE:
        return False
    return True

def is_unixtimestamp_valid(timestamp_unix_ms):
    try:
        datetime.datetime.fromtimestamp(timestamp_unix_ms // 1000)
        return True
    except Exception as e:
        return False

def is_str_instance(value):
    """ 
    Returns true if the value is a str instance
    Support python2.7 and python 3.7+
    """
    if is_python_37():
        return isinstance(value, str)
    else:
        return isinstance(value, basestring)