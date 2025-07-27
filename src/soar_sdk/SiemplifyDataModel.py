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

import base64
import logging
import os
from typing import TYPE_CHECKING, Any

import SiemplifyUtils

if TYPE_CHECKING:
    import datetime

logger = logging.getLogger("simple_example")


class EntityTypes:
    ALERT = "ALERT"
    HOSTNAME = "HOSTNAME"
    USER = "USERUNIQNAME"
    ADDRESS = "ADDRESS"
    MACADDRESS = "MacAddress"
    PROCESS = "PROCESS"
    PARENTPROCESS = "PARENTPROCESS"
    CHILDPROCESS = "CHILDPROCESS"
    FILENAME = "FILENAME"
    FILEHASH = "FILEHASH"
    PARENTHASH = "PARENTHASH"
    CHILDHASH = "CHILDHASH"
    URL = "DestinationURL"
    THREATSIGNATURE = "THREATSIGNATURE"
    EMAILMESSAGE = "EMAILSUBJECT"
    USB = "USB"
    EVENT = "EVENT"
    CVEID = "CVEID"
    DEPLOYMENT = "DEPLOYMENT"
    CREDITCARD = "CREDITCARD"
    PHONENUMBER = "PHONENUMBER"
    CVE = "CVE"
    THREATACTOR = "THREATACTOR"
    THREATCAMPAIGN = "THREATCAMPAIGN"
    GENERIC = "GENERICENTITY"
    SOURCEDOMAIN = "SOURCEDOMAIN"
    DESTINATIONDOMAIN = "DESTINATIONDOMAIN"
    IPSET = "IPSET"
    CLUSTER = "CLUSTER"
    APPLICATION = "APPLICATION"
    DATABASE = "DATABASE"
    POD = "POD"
    CONTAINER = "CONTAINER"
    SERVICE = "SERVICE"
    DOMAIN = "DOMAIN"


class CaseStatus:
    OPEN = "OPEN"
    CLOSE = "CLOSE"


class InsightSeverity:
    INFO = 0
    WARN = 1
    ERROR = 2


class InsightType:
    General = 0
    Entity = 1


class Base:
    def __init__(
        self,
        identifier: str,
        creation_time: int | None = None,
        modification_time: int | None = None,
        additional_properties: dict[str, Any] | None = None,
    ) -> None:
        logger.info("Creating Base model object")
        if self.is_identifier_mandatory:
            if not identifier:
                logger.error("Missing mandatory field: Identifier")
                raise Exception("Identifier is required")

        self.identifier = identifier
        self.creation_time = creation_time
        self.modification_time = modification_time
        self.additional_properties = additional_properties
        logger.info("Base model created successfully")

    @property
    def is_identifier_mandatory(self) -> bool:
        return True


class CyberCaseInfo(Base):
    def __init__(
        self,
        identifier: str,
        creation_time: int,
        modification_time: int,
        alert_count: int,
        priority: int,
        is_touched: bool,
        is_merged: bool,
        is_important: bool,
        assigned_user: str,
        title: str,
        description: str,
        status: str,
        environment: str,
        is_incident: bool,
        stage: str,
        has_suspicious_entity: bool,
        high_risk_products: list[str],
        is_locked: bool,
        has_workflow: bool,
        sla_expiration_unix_time: int,
        additional_properties: dict[str, Any] | None,
    ) -> None:
        logger.info("Creating CyberCaseInfo model object")
        super(CyberCaseInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.environment = environment
        self.priority = priority
        self.is_touched = is_touched
        self.is_merged = is_merged
        self.is_important = is_important
        self.assigned_user = assigned_user
        self.title = title
        self.description = description
        self.status = status
        self.stage = stage
        self.alert_count = alert_count
        self.has_suspicious_entity = has_suspicious_entity
        self.has_workflow = has_workflow
        self.is_locked = is_locked
        self.high_risk_products = high_risk_products
        self.start_time = 0
        self.sla_expiration_unix_time = sla_expiration_unix_time
        self.is_incident = is_incident
        logger.info("CyberCaseInfo model created successfully")

    @property
    def end_time(self) -> int:
        return (
            int(self.additional_properties.get("EndTime", 0)) if self.additional_properties else 0
        )


class AlertInfo(Base):
    def __init__(
        self,
        identifier: str,
        alert_group_identifier: str,
        creation_time: int,
        modification_time: int,
        case_identifier: str,
        reporting_vendor: str,
        reporting_product: str,
        environment: str,
        name: str,
        description: str,
        external_id: str,
        severity: int,
        rule_generator: str,
        tags: list[str],
        detected_time: int,
        additional_properties: dict[str, Any] | None,
        additional_data: dict[str, Any] | None,
    ) -> None:
        logger.info("Creating AlertInfo model object")
        super(AlertInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.identifier = identifier
        self.alert_group_identifier = alert_group_identifier
        self.additional_data = additional_data
        self.case_identifier = case_identifier
        self.reporting_vendor = reporting_vendor
        self.reporting_product = reporting_product
        self.environment = environment
        self.name = name
        self.description = description
        self.external_id = external_id
        self.severity = severity
        self.rule_generator = rule_generator
        self.tags = tags
        self.detected_time = detected_time
        logger.info("AlertInfo model created successfully")


class Attachment(Base):
    def __init__(
        self,
        case_identifier: str,
        alert_identifier: str | None,
        base64_blob: str,
        attachment_type: str,
        name: str,
        description: str | None,
        is_favorite: bool,
        orig_size: int,
        size: int,
    ) -> None:
        super(Attachment, self).__init__(case_identifier)
        logger.info("Creating AlertInfo model object")
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.base64_blob = base64_blob
        self.type = attachment_type
        self.name = name
        self.description = description
        self.is_favorite = is_favorite
        self.orig_size = orig_size
        self.size = size
        logger.info("Attachment model created successfully")

    @staticmethod
    def fromfile(
        path: str,
        case_id: str | None = None,
        alert_identifier: str | None = None,
        description: str | None = None,
        is_favorite: bool = False,
    ) -> Attachment:
        path = path.replace("\\", "/")
        if not os.path.isfile(path):
            raise OSError("File not found")
        name, file_type = os.path.splitext(os.path.split(path)[1])
        with open(path, "rb") as in_file:
            content = in_file.read()

            if SiemplifyUtils.is_python_37():
                base64_blob = base64.b64encode(content).decode()
            else:
                base64_blob = base64.b64encode(content)

        return Attachment(
            case_id,
            alert_identifier,
            base64_blob,
            file_type,
            name,
            description,
            is_favorite,
            len(content),
            len(base64_blob),
        )

    @property
    def is_identifier_mandatory(self) -> bool:
        return False


class SecurityEventInfo(Base):
    def __init__(
        self,
        identifier: str | None = None,
        creation_time: int | None = None,
        modification_time: int | None = None,
        case_identifier: str | None = None,
        alert_identifier: str | None = None,
        name: str | None = None,
        description: str | None = None,
        event_id: str | None = None,
        device_severity: str | None = None,
        device_product: str | None = None,
        device_vendor: str | None = None,
        device_version: str | None = None,
        event_class_id: str | None = None,
        severity: int | None = None,
        start_time: int | None = None,
        end_time: int | None = None,
        event_type: str | None = None,
        rule_generator: str | None = None,
        is_correlation: bool | None = None,
        device_host_name: str | None = None,
        device_address: str | None = None,
        source_dns_domain: str | None = None,
        source_nt_domain: str | None = None,
        source_host_name: str | None = None,
        source_address: str | None = None,
        source_user_name: str | None = None,
        source_user_id: str | None = None,
        source_process_name: str | None = None,
        destination_dns_domain: str | None = None,
        destination_nt_domain: str | None = None,
        destination_host_name: str | None = None,
        destination_address: str | None = None,
        destination_user_name: str | None = None,
        destination_url: str | None = None,
        destination_port: str | None = None,
        destination_process_name: str | None = None,
        file_name: str | None = None,
        file_hash: str | None = None,
        file_type: str | None = None,
        email_subject: str | None = None,
        usb: str | None = None,
        application_protocol: str | None = None,
        transport_protocol: str | None = None,
        category_outcome: str | None = None,
        signature: str | None = None,
        deployment: str | None = None,
        additional_properties: dict[str, Any] | None = None,
        threat_actor: str | None = None,
        source_mac_address: str | None = None,
        destination_mac_address: str | None = None,
        credit_card: str | None = None,
        phone_number: str | None = None,
        cve: str | None = None,
        threat_campaign: str | None = None,
        generic_entity: str | None = None,
        process: str | None = None,
        parent_process: str | None = None,
        parent_hash: str | None = None,
        child_process: str | None = None,
        child_hash: str | None = None,
        source_domain: str | None = None,
        destination_domain: str | None = None,
        ipset: str | None = None,
        cluster: str | None = None,
        application: str | None = None,
        database: str | None = None,
        pod: str | None = None,
        container: str | None = None,
        service: str | None = None,
    ) -> None:
        logger.info("Creating SecurityEventInfo model object")
        super(SecurityEventInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.description = description
        self.name = name
        self.event_id = event_id
        self.source_mac_address = source_mac_address
        self.destination_mac_address = destination_mac_address
        self.credit_card = credit_card
        self.phone_number = phone_number
        self.cve = cve
        self.threat_campaign = threat_campaign
        self.generic_entity = generic_entity
        self.threat_actor = threat_actor
        self.device_product = device_product
        self.device_vendor = device_vendor
        self.device_version = device_version
        self.device_severity = device_severity
        self.event_class_id = event_class_id
        self.severity = severity
        self.start_time = start_time
        self.end_time = end_time
        self.event_type = event_type
        self.file_type = file_type
        self.rule_generator = rule_generator
        self.is_correlation = is_correlation
        self.device_host_name = device_host_name
        self.device_address = device_address
        self.source_dns_domain = source_dns_domain
        self.source_nt_domain = source_nt_domain
        self.source_host_name = source_host_name
        self.source_address = source_address
        self.source_user_name = source_user_name
        self.source_user_id = source_user_id
        self.source_process_name = source_process_name
        self.destination_dns_domain = destination_dns_domain
        self.destination_nt_domain = destination_nt_domain
        self.destination_host_name = destination_host_name
        self.destination_address = destination_address
        self.destination_user_name = destination_user_name
        self.destination_url = destination_url
        self.destination_port = destination_port
        self.destination_process_name = destination_process_name
        self.filename = file_name
        self.file_hash = file_hash
        self.email_subject = email_subject
        self.usb = usb
        self.parent_process = parent_process
        self.parent_hash = parent_hash
        self.child_process = child_process
        self.child_hash = child_hash
        self.application_protocol = application_protocol
        self.transport_protocol = transport_protocol
        self.category_outcome = category_outcome
        self.signature = signature
        self.deployment = deployment
        self.process = process
        self.source_domain = source_domain
        self.destination_domain = destination_domain
        self.ipset = ipset
        self.cluster = cluster
        self.application = application
        self.database = database
        self.pod = pod
        self.container = container
        self.service = service

        logger.info("SecurityEventInfo model created successfully")

    @property
    def is_identifier_mandatory(self) -> bool:
        return False


class DomainRelationInfo(Base):
    def __init__(
        self,
        identifier: str,
        creation_time: int,
        modification_time: int,
        case_identifier: str,
        alert_identifier: str,
        security_event_identifier: str,
        relation_type: str,
        event_id: str,
        from_identifier: str,
        to_identifier: str,
        device_product: str,
        device_vendor: str,
        event_class_id: str,
        severity: int,
        start_time: int,
        end_time: int,
        destination_port: str | None,
        category_outcome: str,
        additional_properties: dict[str, Any] | None,
        to_type: str | None = None,
        from_type: str | None = None,
    ) -> None:
        logger.info("Creating DomainRelationInfo model object")
        super(DomainRelationInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.security_event_identifier = security_event_identifier
        self.type = relation_type
        self.event_id = event_id
        self.from_identifier = from_identifier
        self.to_identifier = to_identifier
        self.device_product = device_product
        self.device_vendor = device_vendor
        self.event_class_id = event_class_id
        self.severity = severity
        self.start_time = start_time
        self.end_time = end_time
        self.destination_port = destination_port
        self.category_outcome = category_outcome
        self.to_type = to_type
        self.from_type = from_type
        logger.info("DomainRelationInfo model created successfully")


class DomainEntityInfo(Base):
    def __init__(
        self,
        identifier: str,
        creation_time: int,
        modification_time: int,
        case_identifier: str,
        alert_identifier: str,
        entity_type: str,
        is_internal: bool,
        is_suspicious: bool,
        is_artifact: bool,
        is_enriched: bool,
        is_vulnerable: bool,
        is_pivot: bool,
        additional_properties: dict[str, Any] | None,
    ) -> None:
        logger.info("Creating DomainEntityInfo model object")
        super(DomainEntityInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.entity_type = entity_type
        self.is_internal = is_internal
        self.is_suspicious = is_suspicious
        self.is_artifact = is_artifact
        self.is_enriched = is_enriched
        self.is_vulnerable = is_vulnerable
        self.is_pivot = is_pivot
        logger.info("DomainEntityInfo model created successfully")

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__

    def _update_internal_properties(self) -> None:
        self.additional_properties["IsInternalAsset"] = str(self.is_internal)
        self.additional_properties["IsEnriched"] = str(self.is_enriched)
        self.additional_properties["IsSuspicious"] = str(self.is_suspicious)
        self.additional_properties["IsVulnerable"] = str(self.is_vulnerable)

    def __repr__(self) -> str:
        return self.identifier

    def __str__(self) -> str:
        return self.identifier


class Alert(AlertInfo):
    def __init__(
        self,
        identifier: str,
        alert_group_identifier: str,
        creation_time: int,
        modification_time: int,
        case_identifier: str,
        reporting_vendor: str,
        reporting_product: str,
        environment: str,
        name: str,
        description: str,
        external_id: str,
        severity: int,
        rule_generator: str,
        tags: list[str],
        detected_time: int,
        security_events: list[dict[str, Any]],
        domain_relations: list[dict[str, Any]],
        domain_entities: list[dict[str, Any]],
        additional_properties: dict[str, Any] | None,
        additional_data: dict[str, Any] | None,
    ) -> None:
        logger.info("Creating Alert model object")
        super(Alert, self).__init__(
            identifier,
            alert_group_identifier,
            creation_time,
            modification_time,
            case_identifier,
            reporting_vendor,
            reporting_product,
            environment,
            name,
            description,
            external_id,
            severity,
            rule_generator,
            tags,
            detected_time,
            additional_properties,
            additional_data,
        )

        self.security_events: list[SecurityEventInfo] = []
        self.relations: list[DomainRelationInfo] = []
        self.entities: list[DomainEntityInfo] = []
        self.tags = tags

        for security_event in security_events:
            self.security_events.append(SecurityEventInfo(**security_event))
        for relation in domain_relations:
            self.relations.append(DomainRelationInfo(**relation))
        for entity in domain_entities:
            self.entities.append(DomainEntityInfo(**entity))

        self.start_time = self.get_alert_start_time(creation_time, security_events)

        logger.info("Alert model created successfully")

    def get_alert_start_time(
        self,
        creation_time: int,
        security_events: list[dict[str, Any]],
    ) -> datetime.datetime:
        min_time = 0

        for sec in security_events:
            sec_start_time = self.get_prop_if_exists(sec, "start_time", 0)
            is_correlation = self.get_prop_if_exists(sec, "is_correlation", False)
            if not is_correlation and sec_start_time != 0:
                if min_time == 0 or sec_start_time < min_time:
                    min_time = sec_start_time

        if min_time == 0:
            min_time = creation_time

        minimum_time = SiemplifyUtils.convert_unixtime_to_datetime(min_time)

        return minimum_time

    @staticmethod
    def get_prop_if_exists(
        dictionary: dict[str, Any],
        prop_name: str,
        default_value: Any,
    ) -> Any:
        result = default_value
        if prop_name in dictionary:
            result = dictionary[prop_name]

        return result


class CyberCase(CyberCaseInfo):
    def __init__(
        self,
        identifier: str,
        creation_time: int,
        modification_time: int,
        alert_count: int,
        priority: int,
        is_touched: bool,
        is_merged: bool,
        is_important: bool,
        environment: str,
        assigned_user: str,
        title: str,
        description: str,
        status: str,
        is_incident: bool,
        stage: str,
        has_suspicious_entity: bool,
        high_risk_products: list[str],
        is_locked: bool,
        has_workflow: bool,
        sla_expiration_unix_time: int,
        cyber_alerts: list[dict[str, Any]],
        additional_properties: dict[str, Any] | None,
    ) -> None:
        logger.info("Creating CyberCase model object")
        super(CyberCase, self).__init__(
            identifier,
            creation_time,
            modification_time,
            alert_count,
            priority,
            is_touched,
            is_merged,
            is_important,
            assigned_user,
            title,
            description,
            status,
            environment,
            is_incident,
            stage,
            has_suspicious_entity,
            high_risk_products,
            is_locked,
            has_workflow,
            sla_expiration_unix_time,
            additional_properties,
        )
        self.alerts = []
        for alert in cyber_alerts:
            self.alerts.append(Alert(**alert))

        logger.info("CyberCase model created successfully")

    def has_alerts_loaded(self) -> bool:
        # Alerts always loaded for CyberCase instance
        return True


class CyberCaseLazy(CyberCaseInfo):
    def __init__(
        self,
        alerts_provider: Any,
        identifier: str,
        creation_time: int,
        modification_time: int,
        alert_count: int,
        priority: int,
        is_touched: bool,
        is_merged: bool,
        is_important: bool,
        environment: str,
        assigned_user: str,
        title: str,
        description: str,
        status: str,
        is_incident: bool,
        stage: str,
        has_suspicious_entity: bool,
        high_risk_products: list[str],
        is_locked: bool,
        has_workflow: bool,
        sla_expiration_unix_time: int,
        additional_properties: dict[str, Any] | None,
    ) -> None:
        logger.info("Creating CyberCaseLazy model object")
        super(CyberCaseLazy, self).__init__(
            identifier,
            creation_time,
            modification_time,
            alert_count,
            priority,
            is_touched,
            is_merged,
            is_important,
            assigned_user,
            title,
            description,
            status,
            environment,
            is_incident,
            stage,
            has_suspicious_entity,
            high_risk_products,
            is_locked,
            has_workflow,
            sla_expiration_unix_time,
            additional_properties,
        )
        self._alerts = None
        self.__alerts_provider = alerts_provider
        logger.info("CyberCaseLazy model created successfully")

    @property
    def alerts(self) -> list[Alert]:
        if self._alerts is None:
            loaded_alerts = self.__alerts_provider.get_alerts()
            self._alerts = [Alert(**alert) for alert in loaded_alerts]

        return self._alerts

    def has_alerts_loaded(self) -> bool:
        return self._alerts is not None


class CaseFilterValue:
    def __init__(self, value: str, title: str) -> None:
        self.value = value
        self.title = title


class CasesFilter:
    def __init__(
        self,
        environments: list[str] | None = None,
        analysts: list[str] | None = None,
        statuses: list[str] | None = None,
        case_names: list[str] | None = None,
        tags: list[str] | None = None,
        priorities: list[int] | None = None,
        stages: list[str] | None = None,
        case_types: list[str] | None = None,
        products: list[str] | None = None,
        networks: list[str] | None = None,
        ticked_ids_free_search: str = "",
        case_ids_free_search: str = "",
        wall_data_free_search: str = "",
        entities_free_search: str = "",
        start_time_unix_time_in_ms: int = -1,
        end_time_unix_time_in_ms: int = -1,
    ) -> None:
        self.ticked_ids_free_search = ticked_ids_free_search
        self.environments = environments or []
        self.case_ids_free_search = case_ids_free_search
        self.products = products or []
        self.analysts = analysts or []
        self.status = statuses or []
        self.tags = tags or []
        self.start_time_unix_time_in_ms = start_time_unix_time_in_ms
        self.end_time_unix_time_in_ms = end_time_unix_time_in_ms
        self.case_names = case_names or []
        self.priorities = priorities or []
        self.wall_data_free_search = wall_data_free_search
        self.stages = stages or []
        self.networks = networks or []
        self.case_types = case_types or []
        self.entities_free_search = entities_free_search


class Task(Base):
    def __init__(
        self,
        case_id: str,
        content: str,
        creator_user_id: str,
        due_date_unix_time_ms: int | None = None,
        is_important: bool = False,
        is_favorite: bool = False,
        owner_comment: str | None = None,
        priority: int = 0,
        owner: str | None = None,
        status: int = 0,
        completion_comment: str | None = None,
        completion_date_time_unix_time_in_ms: int | None = None,
        alert_identifier: str | None = None,
        id: int = 0,
        title: str | None = None,
        creator_full_name: str | None = None,
        owner_full_name: str | None = None,
        creation_time_unix_time_in_ms: int = 0,
        modification_time_unix_time_in_ms: int = 0,
        last_modifier: str | None = None,
        last_modifier_full_name: str | None = None,
        completor: str | None = None,
        completor_full_name: str | None = None,
    ) -> None:
        """Task init
        :param case_id: {int}
        :param title: {str}
        :param content: {str}
        :param creator_user_id: {str}
        :param creator_full_name: {str}
        :param owner_full_name: {str}
        :param last_modifier: {str}
        :param last_modifier_full_name: {str}
        :param completor: {str}
        :param completor_full_name: {str}
        :param creation_time_unix_time_in_ms: {long} #unixtime
        :param due_date_unix_time_ms: {long} #unixtime
        :param is_important: {bool}
        :param is_favorite: {bool}
        :param owner_comment: {str}
        :param priority: {int}
        :param owner: {str}
        :param status: {int}
        :param completion_comment: {str}
        :param completion_date_time_unix_time_in_ms: {long} #unixtime
        :param alert_identifier: {int}
        :param id: {int}
        """
        super(Task, self).__init__(case_id)
        self.case_id = case_id
        self.creation_time_unix_time_in_ms = creation_time_unix_time_in_ms
        self.modification_time_unix_time_in_ms = modification_time_unix_time_in_ms
        self.title = title
        self.content = content
        self.creator_user_id = creator_user_id
        self.creator_full_name = creator_full_name
        self.owner_full_name = owner_full_name
        self.last_modifier = last_modifier
        self.last_modifier_full_name = last_modifier_full_name
        self.completor = completor
        self.completor_full_name = completor_full_name

        # Optional used parameters
        self.due_date_unix_time_ms = due_date_unix_time_ms
        self.is_important = is_important
        self.is_favorite = is_favorite

        # Not used yet (here for later development)
        self.priority = priority
        self.owner_comment = owner_comment

        # Fixed values for first creation
        self.owner = owner if owner else creator_user_id
        self.status = status
        self.completion_comment = completion_comment
        self.completion_date_time_unix_time_in_ms = completion_date_time_unix_time_in_ms

        # DB properties
        self.alert_identifier = alert_identifier
        self.id = id

    @property
    def is_identifier_mandatory(self) -> bool:
        return False


class CustomList(Base):
    def __init__(self, identifier: str, category: str, environment: str) -> None:
        """CustomList init
        :param identifier: {string}
        :param category: {string}
        :param environment: {string}
        """
        super(CustomList, self).__init__(identifier)
        self.identifier = identifier
        self.category = category
        self.environment = environment

    def __str__(self) -> str:
        return f"Identifier: {self.identifier}, Category: {self.category}, Environment: {self.environment}"

    @property
    def is_identifier_mandatory(self) -> bool:
        return False


class LogRecordTypeEnum:
    KEEP_ALIVE = 2
    ERROR = 1
    INFO = 0


class ConnectorLogRecord:
    def __init__(
        self,
        record_type: int,
        message: str,
        connector_identifier: str,
        result_data_type: str,
        original_source_file_name: str | None = None,
        result_package_items_count: int | None = None,
        environment: str | None = None,
        source_system_name: str | None = None,
        exception_message: str | None = None,
        integration: str | None = None,
        connector_definition_name: str | None = None,
        timestamp: int | None = None,
    ) -> None:
        self.RecordType = record_type
        self.Message = message
        self.ConnectorIdentifier = connector_identifier
        self.ResultDataType = result_data_type
        self.OriginalSourceFileName = original_source_file_name
        self.ResultPackageItemsCount = result_package_items_count
        self.Environment = environment
        self.SourceSystemName = source_system_name
        self.ExceptionMessage = exception_message
        self.TimestampUnixMs = timestamp
        self.ConnectorDefinitionName = connector_definition_name
        self.Integration = integration


class ActionLogRecord:
    def __init__(
        self,
        record_type: int,
        message: str,
        original_source_file_name: str | None = None,
        case_id: str | None = None,
        alert_id: str | None = None,
        workflow_id: str | None = None,
        environment: str | None = None,
        source_system_name: str | None = None,
        exception_message: str | None = None,
        integration: str | None = None,
        action_definition_name: str | None = None,
        timestamp: int | None = None,
    ) -> None:
        self.RecordType = record_type
        self.Message = message
        self.CaseId = case_id
        self.AlertId = alert_id
        self.WorkflowId = workflow_id
        self.OriginalSourceFileName = original_source_file_name
        self.Environment = environment
        self.SourceSystemName = source_system_name
        self.ExceptionMessage = exception_message
        self.TimestampUnixMs = timestamp
        self.ActionDefinitionName = action_definition_name
        self.Integration = integration


class LogRow:
    def __init__(self, message: str, log_level: int, timestamp: int) -> None:
        self.message = message
        self.log_level = log_level
        self.timestamp = timestamp


class CaseFilterOperatorEnum:
    OR = "OR"
    AND = "AND"


class CaseFilterStatusEnum:
    OPEN = "OPEN"
    CLOSE = "CLOSE"
    BOTH = "BOTH"


class CaseFilterSortOrderEnum:
    ASC = "ASC"
    DESC = "DESC"


class CaseFilterSortByEnum:
    START_TIME = "START_TIME"
    CLOSE_TIME = "CLOSE_TIME"
    UPDATE_TIME = "UPDATE_TIME"


class ApiSyncCasePriorityEnum:
    INFORMATIVE = 0
    UNCHANGED = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ApiSyncCaseStatusEnum:
    OPENED = 0
    CLOSED = 1
    ALL = 2
    MERGED = 3
    CREATION_PENDING = 4


class ApiSyncAlertPriorityEnum:
    INFORMATIVE = 0
    UNCHANGED = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ApiSyncAlertStatusEnum:
    OPENED = 0
    CLOSED = 1


class ApiSyncAlertCloseReasonEnum:
    MALICIOUS = 0
    NOT_MALICIOUS = 1
    MAINTENANCE = 2
    INCONCLUSIVE = 3
    UNKNOWN = 4


class ApiSyncAlertUsefulnessEnum:
    NONE = 0
    NOT_USEFUL = 1
    USEFUL = 2


class SyncCase:
    def __init__(
        self,
        case_id: int,
        environment: str,
        priority: int,
        stage: str,
        status: int,
        external_case_id: str,
        title: str,
    ) -> None:
        """:param case_id: {int}
        :param environment: {string}
        :param priority: {int} represented by ApiSyncCasePriorityEnum values.
        :param stage: {string}
        :param status: {int} represented by ApiSyncAlertStatusEnum values.
        :param external_case_id: {string}
        :param title: {string}
        """
        self.case_id = case_id
        self.environment = environment
        self.priority = priority
        self.stage = stage
        self.status = status
        self.external_case_id = external_case_id
        self.title = title


class SyncCaseMetadata:
    def __init__(self, case_id: int, tracking_time: int) -> None:
        """:param case_id: {int}
        :param tracking_time: {int} UTC tracking time in ms.
        """
        self.case_id = case_id
        self.tracking_time = tracking_time


class SyncAlert:
    # When an alert's siem_alert_id is set with this value, then, it will not be synced
    # to the SIEM.
    AVOID_ALERT_SYNC = "-1"

    def __init__(
        self,
        alert_group_id: str,
        alert_id: str,
        case_id: int,
        environment: str,
        priority: int,
        status: int,
        ticket_id: str,
        creation_time: int,
        close_comment: str | None,
        close_reason: int | None,
        close_root_cause: str | None,
        close_usefulness: int | None,
        siem_alert_id: str | None = None,
    ) -> None:
        """:param alert_group_id: {string}
        :param alert_id: {string}
        :param case_id: {int}
        :param environment: {string}
        :param priority: {int} represented by ApiSyncAlertPriorityEnum values.
        :param status: {int} represented by ApiSyncAlertStatusEnum values.
        :param ticket_id: {string}
        :param creation_time: {int} UTC creation time in ms.
        :param close_comment: {string} Usable if status ==
        ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param close_reason: {int} represented by ApiSyncAlertCloseReasonEnum values.
        Usable if
            status == ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param close_root_cause: {string} Usable if status ==
        ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param close_usefulness: {int} represented by ApiSyncAlertUsefulnessEnum
        values. Usable if
            status == ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param siem_alert_id: {string} Corresponding Chronicle SIEM alert identifier
        """
        self.alert_group_id = alert_group_id
        self.alert_id = alert_id
        self.case_id = case_id
        self.environment = environment
        self.priority = priority
        self.status = status
        self.ticket_id = ticket_id
        self.creation_time = creation_time
        self.close_comment = close_comment
        self.close_reason = close_reason
        self.close_root_cause = close_root_cause
        self.close_usefulness = close_usefulness
        self.siem_alert_id = siem_alert_id


class SyncAlertMetadata:
    def __init__(self, alert_group_id: str, tracking_time: int) -> None:
        """:param alert_group_id: {string}
        :param tracking_time: {int} UTC tracking time in ms.
        """
        self.alert_group_id = alert_group_id
        self.tracking_time = tracking_time


class SyncCaseIdMatch:
    """This object represents a matching between a Siemplify internal case id and an
    external case id in an
    external system.
    """

    def __init__(self, case_id: int, external_case_id: str) -> None:
        """:param case_id: {int}
        :param external_case_id: {string}
        """
        self.case_id = case_id
        self.external_case_id = external_case_id


class ApiPeriodTypeEnum:
    """This object represents the time units of an SLA period."""

    MINUTES = "Minutes"
    HOURS = "Hours"
    DAYS = "Days"

    @classmethod
    def values(cls):
        return [cls.MINUTES, cls.HOURS, cls.DAYS]

    @classmethod
    def validate(cls, value):
        value_lower = value.lower()
        return (
            value_lower == cls.MINUTES.lower()
            or value_lower == cls.HOURS.lower()
            or value_lower == cls.DAYS.lower()
        )
