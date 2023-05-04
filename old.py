
class AlertInfo(Base):
	def __init__(self, identifier, creation_time, modification_time, case_identifier, reporting_vendor, reporting_product, environment, name, description, external_id, severity, rule_generator, tags, detected_time, additional_properties):
		logger.info("Creating AlertInfo model object")
		Base.__init__(self, identifier, creation_time, modification_time, additional_properties)	
		self.case_identifier = case_identifier
		self.reporting_vendor = reporting_vendor
		self.reporting_product = reporting_product
		self.environment = environment
		self.name = name
		self.description = description
		self.external_id= external_id
		self.severity = severity
		self.rule_generator = rule_generator
		self.tags = tags
		self.detected_time = detected_time
		logger.info("AlertInfo model created successfully")
		
				
class SecurityEventInfo(Base):
    def __init__(self, identifier = None, creation_time = None, modification_time = None, case_identifier = None, alert_identifier = None, name = None, description = None, event_id = None, device_severity = None, device_product = None, device_vendor = None, device_version = None, event_class_id = None, severity = None, 
				start_time = None, end_time = None, event_type = None, rule_generator = None, is_correlation = None, device_host_name = None, device_address = None, source_dns_domain = None, source_nt_domain = None, source_host_name = None, 
				source_address = None, source_user_name = None, source_user_id = None, source_process_name = None, destination_dns_domain = None, destination_nt_domain = None, destination_host_name = None, destination_address = None, 
				destination_user_name = None, destination_url = None, destination_port = None, destination_process_name = None, file_name = None, file_hash = None, file_type = None, email_message = None, usb = None, application_protocol = None, transport_protocol = None,
				category_outcome = None, signature = None, deployment = None, additional_properties = None, destination_mac_address = None, source_mac_address = None, generic_entity = None):
		logger.info("Creating SecurityEventInfo model object")
		Base.__init__(self, identifier, creation_time, modification_time, additional_properties)	
		self.case_identifier = case_identifier
		self.alert_identifier = alert_identifier
		self.event_id = event_id
		self.event_class_id = event_class_id
		self.description = description
		self.name = name
		self.event_type = event_type
		self.rule_generator = rule_generator
		self.is_correlation = is_correlation
		self.severity = severity
		self.category_outcome = category_outcome
		self.start_time = start_time
		self.end_time = end_time
		self.source_host_name = source_host_name
		self.source_address = source_address
		self.source_dns_domain = source_dns_domain
		self.source_nt_domain = source_nt_domain
		self.source_user_name = source_user_name
		self.source_user_id = source_user_id
		self.source_process_name = source_process_name
		self.destination_dns_domain = destination_dns_domain
		self.destination_nt_domain = destination_nt_domain
		self.destination_host_name = destination_host_name
		self.destination_address = destination_address
		self.destination_user_name = destination_user_name
		self.destination_process_name = destination_process_name
		self.transport_protocol = transport_protocol
		self.application_protocol = application_protocol
		self.destination_url = destination_url
		self.destination_port = destination_port
		self.deployment = deployment
		self.filename = file_name
		self.file_hash =file_hash
		self.file_type = file_type
		self.email_message = email_message
		self.signature = signature
		self.usb = usb
		self.device_host_name = device_host_name
		self.device_address = device_address
		self.device_product = device_product
		self.device_vendor = device_vendor
		self.device_version = device_version
		self.device_severity= device_severity
		self.destination_mac_address =  destination_mac_address
		self.source_mac_address = source_mac_address
		self.generic_entity = generic_entity
		logger.info("SecurityEventInfo model created successfully")	


class DomainRelationInfo(Base):
	def __init__(self, identifier, creation_time, modification_time, case_identifier, alert_identifier, security_event_identifier, relation_type, event_id, from_identifier,
				to_identifier, device_product, device_vendor, event_class_id, severity, start_time, end_time, destination_port, category_outcome, additional_properties):
		logger.info("Creating DomainRelationInfo model object")
		Base.__init__(self, identifier, creation_time, modification_time, additional_properties)	
		self.case_identifier = case_identifier
		self.alert_identifier = alert_identifier
		self.security_event_identifier = security_event_identifier
		self.event_id = event_id
		self.from_identifier = from_identifier
		self.to_identifier = to_identifier
		self.device_product = device_product
		self.device_vendor = device_vendor
		self.event_class_id = event_class_id
		self.severity = severity
		self.category_outcome = category_outcome
		self.destination_port = destination_port
		self.start_time = start_time
		self.end_time = end_time
		logger.info("DomainRelationInfo model created successfully")
				
class DomainEntityInfo(Base):
	def __init__(self, identifier, creation_time, modification_time, case_identifier, alert_identifier, entity_type, is_internal, is_suspicious, is_artifact, is_enriched, 
				is_vulnerable, is_pivot, additional_properties):
		logger.info("Creating DomainEntityInfo model object")	
		Base.__init__(self, identifier, creation_time, modification_time, additional_properties)	
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
	def to_dict(self):
		return self.__dict__
	def _update_internal_properties(self):
		self.additional_properties["IsInternalAsset"] = str(self.is_internal)
		self.additional_properties["IsEnriched"] = str(self.is_enriched)
		self.additional_properties["IsSuspicious"] = str(self.is_suspicious)
		self.additional_properties["IsVulnerable"] = str(self.is_vulnerable)

				
class Alert(AlertInfo):
	def __init__(self, identifier, creation_time, modification_time, case_identifier, reporting_vendor, reporting_product, environment, name, description, external_id, 
				severity, rule_generator, tags, detected_time, security_events, domain_relations, domain_entities, additional_properties):
		logger.info("Creating Alert model object")
		AlertInfo.__init__(self,  identifier, creation_time, modification_time, case_identifier, reporting_vendor, reporting_product, environment, name, description, external_id, severity, rule_generator, tags, detected_time, additional_properties)
		self.security_events = []
		self.relations = []
		self.entities = []
		self.tags = tags
		for security_event in security_events:
			self.security_events.append(SecurityEventInfo(**security_event))
		for relation in domain_relations:
			self.relations.append(DomainRelationInfo(**relation))
		for entity in domain_entities:
			self.entities.append(DomainEntityInfo(**entity))
		self.start_time = SiemplifyUtils.from_unix_time(min(self.security_events, key=attrgetter('start_time')).start_time)
		logger.info("Alert model created successfully")	